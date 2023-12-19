/*
    Copyright (c) 2023 Intel Corporation
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at
        http://www.apache.org/licenses/LICENSE-2.0
    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/memory_provider_internal.h"
#include "ravl.h"
#include "umf/providers/provider_coarse.h"
#include "utils_concurrency.h"

#ifndef BYTE
#define BYTE unsigned char
#endif

static enum umf_result_t coarse_memory_provider_alloc(void *provider,
                                                      size_t size,
                                                      size_t alignment,
                                                      void **resultPtr);

static enum umf_result_t coarse_memory_provider_free(void *provider, void *ptr,
                                                     size_t bytes);

static enum umf_result_t
coarse_memory_provider_get_stats(void *provider,
                                 coarse_memory_provider_stats_t *stats);

static void ravl_cb_count(void *data, void *arg);
static void ravl_cb_count_free(void *data, void *arg);

typedef struct block_t {
    size_t size;
    BYTE *data;

    // Origin is the element of the provider's upstream_alloc that contains the
    // beginning of data in current block. Note that data address could be
    // higher than the origin - this means, that the origin allocation
    // covers current block only partially.
    // If the size of the block is greater than the size of the allocation,
    // it means that there are multiple allocations.
    // Note that provider's upstream_alloc doesn't use "origin" and "used" fields.
    struct block_t *origin;
    bool used;

    struct block_t *next;
    struct block_t *prev;

    // Node in the list of free blocks of the same size pointing to this block.
    // The list is located in the (coarse_provider->free_blocks) RAVL tree.
    struct ravl_free_blocks_elem_t *free_list_ptr;
} block_t;

// A general node in a RAVL tree.
// 1) coarse_provider->all_blocks RAVL tree (tree of all blocks - sorted by an address of data):
//    key   - pointer (block_t->data) to the beginning of the block data
//    value - pointer (block_t) to the block of the allocation
// 2) coarse_provider->free_blocks RAVL tree (tree of free blocks - sorted by a size of data):
//    key   - size of the allocation (block_t->size)
//    value - pointer (ravl_free_blocks_head_t) to the head of the list of free blocks of the same size
typedef struct ravl_data_t {
    uintptr_t key;
    void *value;
} ravl_data_t;

// The head of the list of free blocks of the same size,
// so there is a separate mutex for each size.
typedef struct ravl_free_blocks_head_t {
    struct ravl_free_blocks_elem_t *head;
    struct os_mutex_t *mutex;
} ravl_free_blocks_head_t;

// The node of the list of free blocks of the same size
typedef struct ravl_free_blocks_elem_t {
    struct block_t *block;
    struct ravl_free_blocks_elem_t *next;
    struct ravl_free_blocks_elem_t *prev;
} ravl_free_blocks_elem_t;

// The compare function of a RAVL tree
static int ravl_comp(const void *lhs, const void *rhs) {
    ravl_data_t *lhs_ravl = (ravl_data_t *)lhs;
    ravl_data_t *rhs_ravl = (ravl_data_t *)rhs;

    if (lhs_ravl->key < rhs_ravl->key) {
        return -1;
    } else if (lhs_ravl->key == rhs_ravl->key) {
        return 0;
    } else {
        return 1;
    }
}

// The functions "ravl_tree_*" handle lists of blocks:
// - coarse_provider->all_blocks and coarse_provider->upstream_alloc
// sorted by a pointer (block_t->data) to the beginning of the block data.
//
// ravl_tree_add_new - allocate and add a new block to the tree
// and link this block to the next and the previous one.
static block_t *ravl_tree_add_new(struct ravl *rtree, BYTE *data, size_t size) {
    assert(rtree);
    assert(data);
    assert(size);

    // TODO this malloc can be optimized
    block_t *block = (block_t *)malloc(sizeof(block_t));
    if (block == NULL) {
        return NULL;
    }

    block->data = data;
    block->size = size;
    block->next = NULL;
    block->prev = NULL;
    block->free_list_ptr = NULL;

    ravl_data_t rdata = {(uintptr_t)block->data, block};
    assert(NULL == ravl_find(rtree, &data, RAVL_PREDICATE_EQUAL));
    int ret = ravl_emplace_copy(rtree, &rdata);
    if (ret) {
        free(block);
        return NULL;
    }

    struct ravl_node *ravl_node =
        ravl_find(rtree, &rdata, RAVL_PREDICATE_EQUAL);

    assert(ravl_node != NULL);

    struct ravl_node *ravl_next = ravl_node_successor(ravl_node);
    if (ravl_next) {
        ravl_data_t *node_data = ravl_data(ravl_next);
        assert(node_data);
        block->next = node_data->value;
        assert(block->next);
    }

    struct ravl_node *ravl_prev = ravl_node_predecessor(ravl_node);
    if (ravl_prev) {
        ravl_data_t *node_data = ravl_data(ravl_prev);
        assert(node_data);
        block->prev = node_data->value;
        assert(block->prev);
    }

    if (block->next) {
        assert(block->next->prev == block->prev);
        block->next->prev = block;
    }

    if (block->prev) {
        assert(block->prev->next == block->next);
        block->prev->next = block;
    }

    return block;
}

// ravl_tree_find - find the block in the tree
static block_t *ravl_tree_find(struct ravl *rtree, void *ptr) {
    ravl_data_t data = {(uintptr_t)ptr, NULL};
    struct ravl_node *node;
    node = ravl_find(rtree, &data, RAVL_PREDICATE_EQUAL);
    if (node) {
        ravl_data_t *node_data = ravl_data(node);
        assert(node_data);
        return (block_t *)node_data->value;
    }
    return NULL;
}

// ravl_tree_find - remove the block from the tree
static block_t *ravl_tree_rm(struct ravl *rtree, void *ptr) {
    ravl_data_t data = {(uintptr_t)ptr, NULL};
    struct ravl_node *node;
    node = ravl_find(rtree, &data, RAVL_PREDICATE_EQUAL);
    if (node) {
        ravl_data_t *node_data = ravl_data(node);
        assert(node_data);
        block_t *block = node_data->value;
        assert(block);
        ravl_remove(rtree, node);
        assert(NULL == ravl_find(rtree, &data, RAVL_PREDICATE_EQUAL));
        return block;
    }
    return NULL;
}

// The functions "node_list_*" handle lists of free block of the same size.
// The heads (ravl_free_blocks_head_t) of those lists are stored in nodes of
// the coarse_provider->free_blocks RAVL tree.
//
// node_list_add - add a free block to the list of free blocks of the same size
static ravl_free_blocks_elem_t *
node_list_add(ravl_free_blocks_head_t *head_node, struct block_t *block) {
    assert(head_node);
    assert(block);

    // TODO this malloc can be optimized
    ravl_free_blocks_elem_t *node =
        (ravl_free_blocks_elem_t *)malloc(sizeof(ravl_free_blocks_elem_t));
    if (node == NULL) {
        return NULL;
    }

    util_mutex_lock(head_node->mutex);

    if (head_node->head) {
        head_node->head->prev = node;
    }

    node->block = block;
    node->next = head_node->head;
    node->prev = NULL;
    head_node->head = node;

    util_mutex_unlock(head_node->mutex);

    return node;
}

// node_list_rm_first - remove the first free block from the list of free blocks of the same size
static block_t *node_list_rm_first(ravl_free_blocks_head_t *head_node) {
    assert(head_node);

    util_mutex_lock(head_node->mutex);

    if (!head_node->head) {
        util_mutex_unlock(head_node->mutex);
        return NULL;
    }

    ravl_free_blocks_elem_t *node = head_node->head;
    assert(node->prev == NULL);
    if (node->next) {
        node->next->prev = NULL;
    }

    head_node->head = node->next;
    util_mutex_unlock(head_node->mutex);

    struct block_t *block = node->block;
    block->free_list_ptr = NULL;
    free(node);

    return block;
}

// node_list_rm - remove the given free block from the list of free blocks of the same size
static block_t *node_list_rm(ravl_free_blocks_head_t *head_node,
                             ravl_free_blocks_elem_t *node) {
    assert(head_node);
    assert(node);

    util_mutex_lock(head_node->mutex);

    if (!head_node->head) {
        util_mutex_unlock(head_node->mutex);
        return NULL;
    }

    if (node == head_node->head) {
        assert(node->prev == NULL);
        head_node->head = node->next;
    }

    ravl_free_blocks_elem_t *node_next = node->next;
    ravl_free_blocks_elem_t *node_prev = node->prev;
    if (node_next) {
        node_next->prev = node_prev;
    }

    if (node_prev) {
        node_prev->next = node_next;
    }

    util_mutex_unlock(head_node->mutex);
    struct block_t *block = node->block;
    block->free_list_ptr = NULL;
    free(node);

    return block;
}

// The functions "free_blocks_*" handle the coarse_provider->free_blocks RAVL tree
// sorted by a size of the allocation (block_t->size).
// This is a tree of heads (ravl_free_blocks_head_t) of lists of free block of the same size.
//
// free_blocks_add - add a free block to the list of free blocks of the same size
static int free_blocks_add(struct ravl *free_blocks, block_t *block) {
    ravl_free_blocks_head_t *head_node = NULL;
    int rv;

    ravl_data_t head_node_data = {(uintptr_t)block->size, NULL};
    struct ravl_node *node;
    node = ravl_find(free_blocks, &head_node_data, RAVL_PREDICATE_EQUAL);
    if (node) {
        ravl_data_t *node_data = ravl_data(node);
        assert(node_data);
        head_node = node_data->value;
        assert(head_node);
    }

    if (!head_node) {
        // TODO this malloc can be optimized
        head_node = malloc(sizeof(ravl_free_blocks_head_t));
        if (!head_node) {
            return -1;
        }

        head_node->head = NULL;
        head_node->mutex = util_mutex_create();
        if (head_node->mutex == NULL) {
            free(head_node);
            return -1;
        }

        ravl_data_t data = {(uintptr_t)block->size, head_node};
        assert(NULL == ravl_find(free_blocks, &data, RAVL_PREDICATE_EQUAL));
        rv = ravl_emplace_copy(free_blocks, &data);
        if (rv) {
            util_mutex_destroy(head_node->mutex);
            free(head_node);
            return -1;
        }
    }

    block->free_list_ptr = node_list_add(head_node, block);
    if (!block->free_list_ptr) {
        return -1;
    }

    assert(block->free_list_ptr->block->size == block->size);

    return 0;
}

// free_blocks_rm_ge - remove the first free block of a size greater or equal to the given size.
// If it was the last block, the head node is freed and removed from the tree.
// It is used during memory allocation (looking for a free block).
static block_t *free_blocks_rm_ge(struct ravl *free_blocks, size_t size) {
    ravl_data_t data = {(uintptr_t)size, NULL};
    struct ravl_node *node;
    node = ravl_find(free_blocks, &data, RAVL_PREDICATE_GREATER_EQUAL);
    if (!node) {
        return NULL;
    }

    ravl_data_t *node_data = ravl_data(node);
    assert(node_data);
    assert(node_data->key >= size);

    ravl_free_blocks_head_t *head_node = node_data->value;
    assert(head_node);

    block_t *block = node_list_rm_first(head_node);

    if (head_node->head == NULL) {
        util_mutex_destroy(head_node->mutex);
        free(head_node);
        ravl_remove(free_blocks, node);
    }

    return block;
}

// free_blocks_rm_node - remove the free block pointed by the given node.
// If it was the last block, the head node is freed and removed from the tree.
// It is used during merging free blocks and destroying the coarse_provider->free_blocks tree.
static block_t *free_blocks_rm_node(struct ravl *free_blocks,
                                    ravl_free_blocks_elem_t *node) {
    assert(free_blocks);
    assert(node);
    size_t size = node->block->size;
    ravl_data_t data = {(uintptr_t)size, NULL};
    struct ravl_node *ravl_node;
    ravl_node = ravl_find(free_blocks, &data, RAVL_PREDICATE_EQUAL);
    assert(ravl_node);

    ravl_data_t *node_data = ravl_data(ravl_node);
    assert(node_data);
    assert(node_data->key == size);

    ravl_free_blocks_head_t *head_node = node_data->value;
    assert(head_node);

    block_t *block = node_list_rm(head_node, node);

    if (head_node->head == NULL) {
        util_mutex_destroy(head_node->mutex);
        free(head_node);
        ravl_remove(free_blocks, ravl_node);
    }

    return block;
}

// free_block_merge_with_prev - merge the given free block
// with the previous one if both are unused and have continuous data.
// Remove the merged block from the tree of free blocks.
static block_t *free_block_merge_with_prev(
    umf_memory_provider_handle_t upstream_memory_provider,
    struct ravl *all_blocks, struct ravl *free_blocks, block_t *block) {

    assert(all_blocks);
    assert(free_blocks);
    assert(block);
    assert(block->used == false);

    // check if blocks could be merged by the upstream provider
    enum umf_result_t merge_success = UMF_RESULT_ERROR_UNKNOWN;
    if (block->prev && block->prev->used == false &&
        (block->prev->data + block->prev->size == block->data)) {
        merge_success = umfMemoryProviderAllocMerge(
            upstream_memory_provider, block->prev->origin->data,
            block->prev->origin->size, block->origin->data,
            block->origin->size);
    }

    if (merge_success == UMF_RESULT_SUCCESS) {
        block_t *to_free = block;

        if (block->prev->free_list_ptr) {
            free_blocks_rm_node(free_blocks, block->prev->free_list_ptr);
            block->prev->free_list_ptr = NULL;
        }

        // set neighbors
        block->prev->next = block->next;
        block->prev->size += block->size;

        if (block->next) {
            block->next->prev = block->prev;
        }

        block = block->prev;
        block_t *block_rm = ravl_tree_rm(all_blocks, to_free->data);
        assert(block_rm == to_free);
        (void)block_rm; // WA for unused variable error
        free(to_free);
    }

    return block;
}

// free_block_merge_with_next - merge the given free block
// with the next one if both are unused and have continuous data.
// Remove the merged block from the tree of free blocks.
static block_t *free_block_merge_with_next(
    umf_memory_provider_handle_t upstream_memory_provider,
    struct ravl *all_blocks, struct ravl *free_blocks, block_t *block) {

    assert(all_blocks);
    assert(free_blocks);
    assert(block);
    assert(block->used == false);

    // check if blocks could be merged by the upstream provider
    enum umf_result_t merge_success = UMF_RESULT_ERROR_UNKNOWN;
    if (block->next && block->next->used == false &&
        (block->data + block->size == block->next->data)) {
        merge_success = umfMemoryProviderAllocMerge(
            upstream_memory_provider, block->origin->data, block->origin->size,
            block->next->origin->data, block->next->origin->size);
    }

    if (merge_success == UMF_RESULT_SUCCESS) {
        block_t *to_free = block->next;

        if (block->next->free_list_ptr) {
            free_blocks_rm_node(free_blocks, block->next->free_list_ptr);
            block->next->free_list_ptr = NULL;
        }

        assert(block->data < block->next->data);
        assert((block->data + block->size) == block->next->data);

        if (block->next->next) {
            block->next->next->prev = block;
        }

        // set neighbors
        block->size += block->next->size;
        block->next = block->next->next;

        block_t *block_rm = ravl_tree_rm(all_blocks, to_free->data);
        assert(block_rm == to_free);
        (void)block_rm; // WA for unused variable error
        free(to_free);
    }

    return block;
}

// alloc_find_origin - find the upstream allocation that contains data with given offset.
static block_t *alloc_find_origin(block_t *alloc, size_t offset) {
    assert(alloc);

    while (offset >= alloc->size) {
        offset -= alloc->size;
        alloc = alloc->next;
        assert(alloc);
    }

    return alloc;
}

typedef struct coarse_memory_provider_t {
    umf_memory_provider_handle_t upstream_memory_provider;

    size_t used_size;
    size_t alloc_size;

    // upstream_alloc - tree of all blocks allocated from the upstream provider
    struct ravl *upstream_alloc;

    // all_blocks - tree of all blocks - sorted by an address of data
    struct ravl *all_blocks;

    // free_blocks - tree of free blocks - sorted by a size of data,
    // each node contains a pointer (ravl_free_blocks_head_t)
    // to the head of the list of free blocks of the same size
    struct ravl *free_blocks;

    struct os_mutex_t *lock;

    bool trace;
} coarse_memory_provider_t;

#ifndef NDEBUG
// ravl_tree_get_head_block() - find the head (head->prev == NULL) of the all_blocks list.
// It is not used in the critical path.
static block_t *ravl_tree_get_head_block(struct ravl *rtree) {
    // find head of blocks (head->prev == NULL)
    block_t *block = NULL;
    struct ravl_node *rnode = ravl_first(rtree);
    if (!rnode) {
        return NULL;
    }

    ravl_data_t *rdata = ravl_data(rnode);
    assert(rdata);
    block = rdata->value;
    assert(block);
    // make sure it is really the head
    assert(block->prev == NULL);
    return block;
}

static bool debug_check(coarse_memory_provider_t *provider) {
    assert(provider);

    size_t sum_used = 0;
    size_t sum_blocks_size = 0;
    size_t sum_allocs_size = 0;

    coarse_memory_provider_stats_t stats = {0};
    coarse_memory_provider_get_stats(provider, &stats);

    // find the head (head->prev == NULL) of the all_blocks list
    block_t *head = ravl_tree_get_head_block(provider->all_blocks);
    if (stats.blocks_num == 0) {
        assert(head == NULL);
    } else {
        assert(head != NULL);
    }

    // tail of blocks (tail->next == NULL)
    block_t *tail = NULL;

    // count blocks by next
    size_t count_next = 0;
    size_t count_free_next = 0;
    block_t *block = head;
    while (block) {
        count_next++;
        if (!block->used) {
            count_free_next++;
        }
        tail = block;
        block = block->next;
    }
    assert(count_next == stats.blocks_num);
    assert(count_free_next == stats.free_blocks_num);

    // count blocks by prev
    size_t count_prev = 0;
    size_t count_free_prev = 0;
    block = tail;
    while (block) {
        count_prev++;
        if (!block->used) {
            count_free_prev++;
        }
        block = block->prev;
    }
    assert(count_prev == stats.blocks_num);
    assert(count_free_prev == stats.free_blocks_num);

    block = head;
    while (block) {
        assert(block->data);
        assert(block->size > 0);
        assert(block->origin);
        assert(block->origin->data);
        assert(block->data >= block->origin->data);
        assert(block->data < (block->origin->data + block->origin->size));

        // only the HEAD could have an empty prev
        if (block != head) {
            assert(block->prev);
        }

        // check double-linking
        if (block->prev) {
            assert(block->prev->next == block);
        }

        if (block->next) {
            assert(block->next->prev == block);
        }

        // there shouldn't be two adjacent not-used blocks
        // if they allocs are continuous and could be merged
        if (block->prev && block->prev->used == false && block->used == false &&
            (block->prev->data + block->prev->size == block->data)) {
            enum umf_result_t merge_success = umfMemoryProviderAllocMerge(
                provider->upstream_memory_provider, block->prev->origin->data,
                block->prev->origin->size, block->origin->data,
                block->origin->size);
            assert(merge_success != UMF_RESULT_SUCCESS);
        }

        if (block->next && block->next->used == false && block->used == false &&
            (block->data + block->size == block->next->data)) {

            enum umf_result_t merge_success = umfMemoryProviderAllocMerge(
                provider->upstream_memory_provider, block->origin->data,
                block->origin->size, block->next->origin->data,
                block->next->origin->size);
            assert(merge_success != UMF_RESULT_SUCCESS);
        }

        // data addresses in the list are in ascending order
        if (block->prev) {
            assert(block->prev->data < block->data);
        }

        if (block->next) {
            assert(block->data < block->next->data);
        }

        // two block's data should not overlap
        if (block->next) {
            assert((block->data + block->size) <= block->next->data);
        }

        // allocs used in block should be continuous
        block_t *alloc = block->origin;
        size_t alloc_offset = block->data - block->origin->data;
        size_t block_size_w_off = block->size + alloc_offset;
        size_t allocs_sum = alloc->size;
        while (allocs_sum < block_size_w_off) {
            assert(alloc->next);
            assert((alloc->data + alloc->size) == alloc->next->data);
            alloc = alloc->next;
            allocs_sum += alloc->size;
        }

        sum_blocks_size += block->size;
        if (block->used) {
            sum_used += block->size;
        }

        block = block->next;
    }

    assert(sum_used == provider->used_size);
    assert(sum_blocks_size == provider->alloc_size);
    assert(provider->alloc_size >= provider->used_size);

    count_next = 0;

    // find head of blocks (head->prev == NULL)
    head = ravl_tree_get_head_block(provider->upstream_alloc);
    block_t *alloc = head;
    while (alloc) {
        assert(alloc->data);
        assert(alloc->size > 0);

        // only the HEAD could have an empty prev
        if (alloc != head) {
            assert(alloc->prev);
        }

        // check double-linking
        if (alloc->prev) {
            assert(alloc->prev->next == alloc);
        }

        if (alloc->next) {
            assert(alloc->next->prev == alloc);
        }

        // data addresses in the list are in ascending order
        if (alloc->prev) {
            assert(alloc->prev->data < alloc->data);
        }

        if (alloc->next) {
            assert(alloc->data < alloc->next->data);
        }

        // data should not overlap
        if (alloc->next) {
            assert((alloc->data + alloc->size) <= alloc->next->data);
        }

        sum_allocs_size += alloc->size;
        count_next++;

        alloc = alloc->next;
    }

    assert(sum_allocs_size == provider->alloc_size);
    assert(count_next == stats.upstream_blocks_num);

    return true;
}
#endif

static enum umf_result_t coarse_memory_provider_initialize(void *params,
                                                           void **provider) {
    void *init_buffer = NULL;

    if (provider == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (params == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    // check params
    coarse_memory_provider_params_t *coarse_params =
        (coarse_memory_provider_params_t *)params;
    if (coarse_params->upstream_memory_provider == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    coarse_memory_provider_t *coarse_provider =
        (coarse_memory_provider_t *)malloc(sizeof(coarse_memory_provider_t));

    if (!coarse_provider) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    coarse_provider->lock = util_mutex_create();
    if (coarse_provider->lock == NULL) {
        goto err_free_coarse_provider;
    }

    coarse_provider->trace = coarse_params->trace;
    coarse_provider->upstream_memory_provider =
        coarse_params->upstream_memory_provider;
    coarse_provider->upstream_alloc =
        ravl_new_sized(ravl_comp, sizeof(ravl_data_t));
    if (coarse_provider->upstream_alloc == NULL) {
        goto err_util_mutex_destroy;
    }
    coarse_provider->free_blocks =
        ravl_new_sized(ravl_comp, sizeof(ravl_data_t));
    if (coarse_provider->free_blocks == NULL) {
        goto err_delete_ravl_upstream_alloc;
    }
    coarse_provider->all_blocks =
        ravl_new_sized(ravl_comp, sizeof(ravl_data_t));
    if (coarse_provider->all_blocks == NULL) {
        goto err_delete_ravl_free_blocks;
    }

    coarse_provider->alloc_size = 0;
    coarse_provider->used_size = 0;

    if (coarse_params->immediate_init) {
        coarse_memory_provider_alloc(
            coarse_provider, coarse_params->init_buffer_size, 0, &init_buffer);

        if (init_buffer == NULL) {
            goto err_delete_ravl_all_blocks;
        }

        coarse_memory_provider_free(coarse_provider, init_buffer,
                                    coarse_params->init_buffer_size);

        // since we use alloc and free functions, we have set the block as unused
        assert(coarse_provider->used_size == 0);
        assert(coarse_provider->alloc_size == coarse_params->init_buffer_size);
    }

    *provider = coarse_provider;

    assert(debug_check(coarse_provider));

    return UMF_RESULT_SUCCESS;

err_delete_ravl_all_blocks:
    ravl_delete(coarse_provider->all_blocks);
err_delete_ravl_free_blocks:
    ravl_delete(coarse_provider->free_blocks);
err_delete_ravl_upstream_alloc:
    ravl_delete(coarse_provider->upstream_alloc);
err_util_mutex_destroy:
    util_mutex_destroy(coarse_provider->lock);
err_free_coarse_provider:
    free(coarse_provider);
    return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
}

static void ravl_cb_rm_upstream_alloc_node(void *data, void *arg) {
    assert(data);
    assert(arg);

    coarse_memory_provider_t *coarse_provider =
        (struct coarse_memory_provider_t *)arg;
    ravl_data_t *node_data = data;
    block_t *alloc = node_data->value;
    assert(alloc);

    enum umf_result_t ret = umfMemoryProviderFree(
        coarse_provider->upstream_memory_provider, alloc->data, alloc->size);

    // We would continue to deallocate alloc blocks even if the upstream
    // provider doesn't return success.
    assert(ret == UMF_RESULT_SUCCESS);
    (void)ret;

    assert(coarse_provider->alloc_size >= alloc->size);
    coarse_provider->alloc_size -= alloc->size;

    free(alloc);
}

static void ravl_cb_rm_all_blocks_node(void *data, void *arg) {
    assert(data);
    assert(arg);

    coarse_memory_provider_t *coarse_provider =
        (struct coarse_memory_provider_t *)arg;
    ravl_data_t *node_data = data;
    block_t *block = node_data->value;
    assert(block);

    if (block->used) {
        assert(coarse_provider->used_size >= block->size);
        coarse_provider->used_size -= block->size;
    }

    if (block->free_list_ptr) {
        free_blocks_rm_node(coarse_provider->free_blocks, block->free_list_ptr);
    }

    free(block);
}

static void coarse_memory_provider_finalize(void *provider) {
    if (provider == NULL) {
        assert(0);
        return;
    }

    coarse_memory_provider_t *coarse_provider =
        (struct coarse_memory_provider_t *)provider;

    ravl_foreach(coarse_provider->upstream_alloc,
                 ravl_cb_rm_upstream_alloc_node, coarse_provider);
    assert(coarse_provider->alloc_size == 0);

    ravl_foreach(coarse_provider->all_blocks, ravl_cb_rm_all_blocks_node,
                 coarse_provider);
    assert(coarse_provider->used_size == 0);

    ravl_delete(coarse_provider->upstream_alloc);
    ravl_delete(coarse_provider->all_blocks);
    ravl_delete(coarse_provider->free_blocks);

    util_mutex_destroy(coarse_provider->lock);
    free(coarse_provider);
}

static enum umf_result_t coarse_memory_provider_alloc(void *provider,
                                                      size_t size,
                                                      size_t alignment,
                                                      void **resultPtr) {
    enum umf_result_t ret = UMF_RESULT_SUCCESS;
    int rv;

    if (provider == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (resultPtr == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    coarse_memory_provider_t *coarse_provider =
        (struct coarse_memory_provider_t *)provider;
    assert(debug_check(coarse_provider));

    if (util_mutex_lock(coarse_provider->lock) != 0) {
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    // Find first blocks with greater or equal size.
    // If the block that we want to reuse has greater size, split it.
    // Try to merge split part with the successor if it is not used.
    block_t *curr = free_blocks_rm_ge(coarse_provider->free_blocks, size);
    if (curr && curr->size > size) {
        assert(curr->used == false);
        // Split the existing block and put the new block after the existing.
        // Find the origin of the new block.
        size_t curr_offset = curr->data - curr->origin->data;
        block_t *origin = alloc_find_origin(curr->origin, curr_offset + size);
        assert(origin);
        void *data = curr->data + size;

        block_t *new_block = ravl_tree_add_new(coarse_provider->all_blocks,
                                               data, curr->size - size);
        if (new_block == NULL) {
            if (util_mutex_unlock(coarse_provider->lock) != 0) {
                return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
            }

            return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        }

        new_block->origin = origin;
        new_block->used = false;

        curr->used = true;
        curr->size = size;

        *resultPtr = curr->data;
        coarse_provider->used_size += size;

        // Try to merge new empty block with the next one.
        new_block = free_block_merge_with_next(
            coarse_provider->upstream_memory_provider,
            coarse_provider->all_blocks, coarse_provider->free_blocks,
            new_block);
        rv = free_blocks_add(coarse_provider->free_blocks, new_block);
        if (rv) {
            return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        }

        if (coarse_provider->trace) {
            printf("coarse_ALLOC (split_block) %zu used %zu alloc %zu\n", size,
                   coarse_provider->used_size, coarse_provider->alloc_size);
        }

        if (util_mutex_unlock(coarse_provider->lock) != 0) {
            return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
        }

        assert(debug_check(coarse_provider));
        return UMF_RESULT_SUCCESS;

    } else if (curr && curr->size == size) {
        assert(curr->used == false);
        curr->used = true;
        *resultPtr = curr->data;
        coarse_provider->used_size += size;

        if (coarse_provider->trace) {
            printf("coarse_ALLOC (same_block) %zu used %zu alloc %zu\n", size,
                   coarse_provider->used_size, coarse_provider->alloc_size);
        }

        if (util_mutex_unlock(coarse_provider->lock) != 0) {
            return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
        }

        assert(debug_check(coarse_provider));
        return UMF_RESULT_SUCCESS;
    }

    // no suitable block - try to get more memory from the upstream provider
    assert(coarse_provider->upstream_memory_provider);

    umfMemoryProviderAlloc(coarse_provider->upstream_memory_provider, size,
                           alignment, resultPtr);
    if (*resultPtr == NULL) {
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    block_t *alloc =
        ravl_tree_add_new(coarse_provider->upstream_alloc, *resultPtr, size);
    if (alloc == NULL) {
        ret = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        goto alloc_error;
    }

    block_t *new_block =
        ravl_tree_add_new(coarse_provider->all_blocks, *resultPtr, size);
    if (new_block == NULL) {
        assert(0);
        ret = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        goto block_error;
    }

    new_block->used = true;
    new_block->origin = alloc;

    coarse_provider->alloc_size += size;
    coarse_provider->used_size += size;

    if (coarse_provider->trace) {
        printf("coarse_ALLOC (upstream) %zu used %zu alloc %zu\n", size,
               coarse_provider->used_size, coarse_provider->alloc_size);
    }

    if (util_mutex_unlock(coarse_provider->lock) != 0) {
        assert(0);
        ret = UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
        goto unlock_error;
    }

    assert(debug_check(coarse_provider));
    return UMF_RESULT_SUCCESS;

unlock_error:
    ravl_tree_rm(coarse_provider->all_blocks, *resultPtr);

block_error:
    ravl_tree_rm(coarse_provider->upstream_alloc, *resultPtr);

alloc_error:
    umfMemoryProviderFree(coarse_provider->upstream_memory_provider, *resultPtr,
                          size);
    return ret;
}

static enum umf_result_t coarse_memory_provider_free(void *provider, void *ptr,
                                                     size_t bytes) {
    if (provider == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    coarse_memory_provider_t *coarse_provider =
        (struct coarse_memory_provider_t *)provider;
    assert(debug_check(coarse_provider));

    if (util_mutex_lock(coarse_provider->lock) != 0) {
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    block_t *block = ravl_tree_find(coarse_provider->all_blocks, ptr);
    if (block == NULL) {
        // the block was not found
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    if (bytes) {
        assert(bytes == block->size);
    }

    if (coarse_provider->trace) {
        printf("coarse_FREE (return_block_to_pool) %zu used %zu alloc %zu\n",
               block->size, coarse_provider->used_size - block->size,
               coarse_provider->alloc_size);
    }

    assert(coarse_provider->used_size >= block->size);
    coarse_provider->used_size -= block->size;

    block->used = false;

    // Merge with prev and/or next block if they are unused and have continuous data.
    block = free_block_merge_with_prev(
        coarse_provider->upstream_memory_provider, coarse_provider->all_blocks,
        coarse_provider->free_blocks, block);
    block = free_block_merge_with_next(
        coarse_provider->upstream_memory_provider, coarse_provider->all_blocks,
        coarse_provider->free_blocks, block);

    int rv = free_blocks_add(coarse_provider->free_blocks, block);
    if (rv) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    assert(debug_check(coarse_provider));

    if (util_mutex_unlock(coarse_provider->lock) != 0) {
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    return UMF_RESULT_SUCCESS;
}

static void coarse_memory_provider_get_last_native_error(void *provider,
                                                         const char **ppMessage,
                                                         int32_t *pError) {
    if (provider == NULL) {
        return;
    }

    (void)ppMessage;
    (void)pError;
    assert(0);
}

static enum umf_result_t
coarse_memory_provider_get_min_page_size(void *provider, void *ptr,
                                         size_t *pageSize) {
    if (provider == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    coarse_memory_provider_t *coarse_provider =
        (struct coarse_memory_provider_t *)provider;

    assert(coarse_provider->upstream_memory_provider);
    enum umf_result_t ret = umfMemoryProviderGetMinPageSize(
        coarse_provider->upstream_memory_provider, ptr, pageSize);

    return ret;
}

static enum umf_result_t
coarse_memory_provider_get_recommended_page_size(void *provider, size_t size,
                                                 size_t *pageSize) {
    if (provider == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    coarse_memory_provider_t *coarse_provider =
        (struct coarse_memory_provider_t *)provider;

    assert(coarse_provider->upstream_memory_provider);
    enum umf_result_t ret = umfMemoryProviderGetRecommendedPageSize(
        coarse_provider->upstream_memory_provider, size, pageSize);

    return ret;
}

static const char *coarse_memory_provider_get_name(void *provider) {
    (void)provider;

    return "coarse";
}

static enum umf_result_t
coarse_memory_provider_get_stats(void *provider,
                                 coarse_memory_provider_stats_t *stats) {
    if (provider == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (stats == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    coarse_memory_provider_t *coarse_provider =
        (struct coarse_memory_provider_t *)provider;

    // count blocks
    size_t upstream_blocks_num = 0;
    ravl_foreach(coarse_provider->upstream_alloc, ravl_cb_count,
                 &upstream_blocks_num);

    size_t blocks_num = 0;
    ravl_foreach(coarse_provider->all_blocks, ravl_cb_count, &blocks_num);

    size_t free_blocks_num = 0;
    ravl_foreach(coarse_provider->free_blocks, ravl_cb_count_free,
                 &free_blocks_num);

    stats->alloc_size = coarse_provider->alloc_size;
    stats->used_size = coarse_provider->used_size;
    stats->upstream_blocks_num = upstream_blocks_num;
    stats->blocks_num = blocks_num;
    stats->free_blocks_num = free_blocks_num;

    return UMF_RESULT_SUCCESS;
}

struct umf_memory_provider_ops_t UMF_COARSE_MEMORY_PROVIDER_OPS = {
    .version = UMF_VERSION_CURRENT,
    .initialize = coarse_memory_provider_initialize,
    .finalize = coarse_memory_provider_finalize,
    .alloc = coarse_memory_provider_alloc,
    .free = coarse_memory_provider_free,
    .get_last_native_error = coarse_memory_provider_get_last_native_error,
    .get_recommended_page_size =
        coarse_memory_provider_get_recommended_page_size,
    .get_min_page_size = coarse_memory_provider_get_min_page_size,
    .get_name = coarse_memory_provider_get_name,
};

static void ravl_cb_count(void *data, void *arg) {
    assert(arg);
    (void)data; /* unused */

    size_t *blocks_num = arg;
    (*blocks_num)++;
}

static void ravl_cb_count_free(void *data, void *arg) {
    assert(data);
    assert(arg);

    ravl_data_t *node_data = data;
    assert(node_data);
    ravl_free_blocks_head_t *head_node = node_data->value;
    assert(head_node);
    struct ravl_free_blocks_elem_t *free_block = head_node->head;
    assert(free_block);

    size_t *blocks_num = arg;
    while (free_block) {
        (*blocks_num)++;
        free_block = free_block->next;
    }
}

coarse_memory_provider_stats_t
umfCoarseMemoryProviderGetStats(umf_memory_provider_handle_t provider) {
    assert(provider);
    void *priv = umfMemoryProviderGetPriv(provider);

    coarse_memory_provider_stats_t stats = {0};
    coarse_memory_provider_get_stats(priv, &stats);

    return stats;
}

umf_memory_provider_handle_t umfCoarseMemoryProviderGetUpstreamProvider(
    umf_memory_provider_handle_t provider) {
    assert(provider);

    coarse_memory_provider_t *coarse_provider =
        (struct coarse_memory_provider_t *)umfMemoryProviderGetPriv(provider);

    return coarse_provider->upstream_memory_provider;
}
