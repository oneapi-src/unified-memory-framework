/*
 * Copyright (C) 2024-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <umf.h>

#include "base_alloc_global.h"
#include "coarse.h"
#include "libumf.h"
#include "ravl.h"
#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_log.h"

#ifdef _WIN32
UTIL_ONCE_FLAG Log_initialized = UTIL_ONCE_FLAG_INIT;
#else
void __attribute__((constructor)) coarse_init(void) { utils_log_init(); }
void __attribute__((destructor)) coarse_destroy(void) {}
#endif /* _WIN32 */

typedef struct coarse_t {
    // handle of the memory provider
    void *provider;

    // coarse callbacks
    coarse_callbacks_t cb;

    // memory allocation strategy
    coarse_strategy_t allocation_strategy;

    // page size of the memory provider
    size_t page_size;

    // all_blocks - tree of all blocks - sorted by an address of data
    struct ravl *all_blocks;

    // free_blocks - tree of free blocks - sorted by a size of data,
    // each node contains a pointer (ravl_free_blocks_head_t)
    // to the head of the list of free blocks of the same size
    struct ravl *free_blocks;

    struct utils_mutex_t lock;

    // statistics
    size_t used_size;
    size_t alloc_size;
} coarse_t;

typedef struct ravl_node ravl_node_t;

typedef enum check_free_blocks_t {
    CHECK_ONLY_THE_FIRST_BLOCK = 0,
    CHECK_ALL_BLOCKS_OF_SIZE,
} check_free_blocks_t;

typedef struct block_t {
    size_t size;
    unsigned char *data;
    bool used;

    // Node in the list of free blocks of the same size pointing to this block.
    // The list is located in the (coarse->free_blocks) RAVL tree.
    struct ravl_free_blocks_elem_t *free_list_ptr;
} block_t;

// A general node in a RAVL tree.
// 1) coarse->all_blocks RAVL tree (tree of all blocks - sorted by an address of data):
//    key   - pointer (block_t->data) to the beginning of the block data
//    value - pointer (block_t) to the block of the allocation
// 2) coarse->free_blocks RAVL tree (tree of free blocks - sorted by a size of data):
//    key   - size of the allocation (block_t->size)
//    value - pointer (ravl_free_blocks_head_t) to the head of the list of free blocks of the same size
typedef struct ravl_data_t {
    uintptr_t key;
    void *value;
} ravl_data_t;

// The head of the list of free blocks of the same size.
typedef struct ravl_free_blocks_head_t {
    struct ravl_free_blocks_elem_t *head;
} ravl_free_blocks_head_t;

// The node of the list of free blocks of the same size
typedef struct ravl_free_blocks_elem_t {
    struct block_t *block;
    struct ravl_free_blocks_elem_t *next;
    struct ravl_free_blocks_elem_t *prev;
} ravl_free_blocks_elem_t;

// The compare function of a RAVL tree
static int coarse_ravl_comp(const void *lhs, const void *rhs) {
    const ravl_data_t *lhs_ravl = (const ravl_data_t *)lhs;
    const ravl_data_t *rhs_ravl = (const ravl_data_t *)rhs;

    if (lhs_ravl->key < rhs_ravl->key) {
        return -1;
    }

    if (lhs_ravl->key > rhs_ravl->key) {
        return 1;
    }

    // lhs_ravl->key == rhs_ravl->key
    return 0;
}

static inline block_t *get_node_block(ravl_node_t *node) {
    ravl_data_t *node_data = ravl_data(node);
    assert(node_data);
    assert(node_data->value);
    return node_data->value;
}

static inline ravl_node_t *get_node_prev(ravl_node_t *node) {
    return ravl_node_predecessor(node);
}

static inline ravl_node_t *get_node_next(ravl_node_t *node) {
    return ravl_node_successor(node);
}

#ifndef NDEBUG
static block_t *get_block_prev(ravl_node_t *node) {
    ravl_node_t *ravl_prev = ravl_node_predecessor(node);
    if (!ravl_prev) {
        return NULL;
    }

    return get_node_block(ravl_prev);
}

static block_t *get_block_next(ravl_node_t *node) {
    ravl_node_t *ravl_next = ravl_node_successor(node);
    if (!ravl_next) {
        return NULL;
    }

    return get_node_block(ravl_next);
}
#endif /* NDEBUG */

// The functions "coarse_ravl_*" handles the coarse->all_blocks list of blocks
// sorted by a pointer (block_t->data) to the beginning of the block data.
//
// coarse_ravl_add_new - allocate and add a new block to the tree
// and link this block to the next and the previous one.
static block_t *coarse_ravl_add_new(struct ravl *rtree, unsigned char *data,
                                    size_t size, ravl_node_t **node) {
    assert(rtree);
    assert(data);
    assert(size);

    // TODO add valgrind annotations
    block_t *block = umf_ba_global_alloc(sizeof(*block));
    if (block == NULL) {
        return NULL;
    }

    block->data = data;
    block->size = size;
    block->free_list_ptr = NULL;

    ravl_data_t rdata = {(uintptr_t)block->data, block};
    assert(NULL == ravl_find(rtree, &data, RAVL_PREDICATE_EQUAL));
    int ret = ravl_emplace_copy(rtree, &rdata);
    if (ret) {
        umf_ba_global_free(block);
        return NULL;
    }

    ravl_node_t *new_node = ravl_find(rtree, &rdata, RAVL_PREDICATE_EQUAL);
    assert(NULL != new_node);

    if (node) {
        *node = new_node;
    }

    return block;
}

// coarse_ravl_find_node - find the node in the tree
static ravl_node_t *coarse_ravl_find_node(struct ravl *rtree, void *ptr) {
    ravl_data_t data = {(uintptr_t)ptr, NULL};
    return ravl_find(rtree, &data, RAVL_PREDICATE_EQUAL);
}

// coarse_ravl_rm - remove the block from the tree
static block_t *coarse_ravl_rm(struct ravl *rtree, void *ptr) {
    ravl_data_t data = {(uintptr_t)ptr, NULL};
    ravl_node_t *node;
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

// The functions "node_list_*" handle lists of free blocks of the same size.
// The heads (ravl_free_blocks_head_t) of those lists are stored in nodes of
// the coarse->free_blocks RAVL tree.
//
// node_list_add - add a free block to the list of free blocks of the same size
static ravl_free_blocks_elem_t *
node_list_add(ravl_free_blocks_head_t *head_node, struct block_t *block) {
    assert(head_node);
    assert(block);

    ravl_free_blocks_elem_t *node = umf_ba_global_alloc(sizeof(*node));
    if (node == NULL) {
        return NULL;
    }

    if (head_node->head) {
        head_node->head->prev = node;
    }

    node->block = block;
    node->next = head_node->head;
    node->prev = NULL;
    head_node->head = node;

    return node;
}

// node_list_rm - remove the given free block from the list of free blocks of the same size
static block_t *node_list_rm(ravl_free_blocks_head_t *head_node,
                             ravl_free_blocks_elem_t *node) {
    assert(head_node);
    assert(node);
    assert(head_node->head);

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

    struct block_t *block = node->block;
    block->free_list_ptr = NULL;
    umf_ba_global_free(node);

    return block;
}

// node_list_rm_first - remove the first free block from the list of free blocks of the same size only if it can be properly aligned
static block_t *node_list_rm_first(ravl_free_blocks_head_t *head_node,
                                   size_t alignment) {
    assert(head_node);
    assert(head_node->head);

    ravl_free_blocks_elem_t *node = head_node->head;
    assert(node->prev == NULL);
    struct block_t *block = node->block;

    if (IS_NOT_ALIGNED(((uintptr_t)block->data), alignment)) {
        return NULL;
    }

    if (node->next) {
        node->next->prev = NULL;
    }

    head_node->head = node->next;
    block->free_list_ptr = NULL;
    umf_ba_global_free(node);

    return block;
}

// node_list_rm_with_alignment - remove the first free block with the correct alignment from the list of free blocks of the same size
static block_t *node_list_rm_with_alignment(ravl_free_blocks_head_t *head_node,
                                            size_t alignment) {
    assert(head_node);
    assert(head_node->head);

    assert(((ravl_free_blocks_elem_t *)head_node->head)->prev == NULL);

    ravl_free_blocks_elem_t *node;
    for (node = head_node->head; node != NULL; node = node->next) {
        if (IS_ALIGNED(((uintptr_t)node->block->data), alignment)) {
            return node_list_rm(head_node, node);
        }
    }

    return NULL;
}

// The functions "free_blocks_*" handle the coarse->free_blocks RAVL tree
// sorted by a size of the allocation (block_t->size).
// This is a tree of heads (ravl_free_blocks_head_t) of lists of free blocks of the same size.
//
// free_blocks_add - add a free block to the list of free blocks of the same size
static int free_blocks_add(struct ravl *free_blocks, block_t *block) {
    ravl_free_blocks_head_t *head_node = NULL;
    int rv;

    ravl_data_t head_node_data = {(uintptr_t)block->size, NULL};
    ravl_node_t *node;
    node = ravl_find(free_blocks, &head_node_data, RAVL_PREDICATE_EQUAL);
    if (node) {
        ravl_data_t *node_data = ravl_data(node);
        assert(node_data);
        head_node = node_data->value;
        assert(head_node);
    } else { // no head_node
        head_node = umf_ba_global_alloc(sizeof(*head_node));
        if (!head_node) {
            return -1;
        }

        head_node->head = NULL;

        ravl_data_t data = {(uintptr_t)block->size, head_node};
        rv = ravl_emplace_copy(free_blocks, &data);
        if (rv) {
            umf_ba_global_free(head_node);
            return -1;
        }
    }

    block->free_list_ptr = node_list_add(head_node, block);
    if (!block->free_list_ptr) {
        return -1; // out of memory
    }

    assert(block->free_list_ptr->block->size == block->size);

    return 0;
}

// free_blocks_rm_ge - remove the first free block of a size greater or equal to the given size only if it can be properly aligned
// If it was the last block, the head node is freed and removed from the tree.
// It is used during memory allocation (looking for a free block).
static block_t *free_blocks_rm_ge(struct ravl *free_blocks, size_t size,
                                  size_t alignment,
                                  check_free_blocks_t check_blocks) {
    ravl_data_t data = {(uintptr_t)size, NULL};
    ravl_node_t *node;
    node = ravl_find(free_blocks, &data, RAVL_PREDICATE_GREATER_EQUAL);
    if (!node) {
        return NULL;
    }

    ravl_data_t *node_data = ravl_data(node);
    assert(node_data);
    assert(node_data->key >= size);

    ravl_free_blocks_head_t *head_node = node_data->value;
    assert(head_node);

    block_t *block = NULL;
    switch (check_blocks) {
    case CHECK_ONLY_THE_FIRST_BLOCK:
        block = node_list_rm_first(head_node, alignment);
        break;
    case CHECK_ALL_BLOCKS_OF_SIZE:
        block = node_list_rm_with_alignment(head_node, alignment);
        break;
    }

    if (head_node->head == NULL) {
        umf_ba_global_free(head_node);
        ravl_remove(free_blocks, node);
    }

    return block;
}

// free_blocks_rm_node - remove the free block pointed by the given node.
// If it was the last block, the head node is freed and removed from the tree.
// It is used during merging free blocks and destroying the coarse->free_blocks tree.
static block_t *free_blocks_rm_node(struct ravl *free_blocks,
                                    ravl_free_blocks_elem_t *node) {
    assert(free_blocks);
    assert(node);
    size_t size = node->block->size;
    ravl_data_t data = {(uintptr_t)size, NULL};
    ravl_node_t *ravl_node;
    ravl_node = ravl_find(free_blocks, &data, RAVL_PREDICATE_EQUAL);
    assert(ravl_node);

    ravl_data_t *node_data = ravl_data(ravl_node);
    assert(node_data);
    assert(node_data->key == size);

    ravl_free_blocks_head_t *head_node = node_data->value;
    assert(head_node);

    block_t *block = node_list_rm(head_node, node);

    if (head_node->head == NULL) {
        umf_ba_global_free(head_node);
        ravl_remove(free_blocks, ravl_node);
    }

    return block;
}

// user_block_merge - merge two blocks from one of two lists of user blocks: all_blocks or free_blocks
static umf_result_t user_block_merge(coarse_t *coarse, ravl_node_t *node1,
                                     ravl_node_t *node2, bool used,
                                     ravl_node_t **merged_node) {
    assert(node1);
    assert(node2);
    assert(node1 == get_node_prev(node2));
    assert(node2 == get_node_next(node1));
    assert(merged_node);

    *merged_node = NULL;

    struct ravl *all_blocks = coarse->all_blocks;
    struct ravl *free_blocks = coarse->free_blocks;

    block_t *block1 = get_node_block(node1);
    block_t *block2 = get_node_block(node2);
    assert(block1->data < block2->data);

    bool same_used = ((block1->used == used) && (block2->used == used));
    bool contignous_data = (block1->data + block1->size == block2->data);

    // check if blocks can be merged
    if (!same_used || !contignous_data) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    // check if blocks can be merged
    umf_result_t umf_result =
        coarse->cb.merge(coarse->provider, block1->data, block2->data,
                         block1->size + block2->size);
    if (umf_result != UMF_RESULT_SUCCESS) {
        LOG_ERR("coarse_merge_cb(lowPtr=%p, highPtr=%p, totalSize=%zu) failed",
                (void *)block1->data, (void *)block2->data,
                block1->size + block2->size);
        return umf_result;
    }

    if (block1->free_list_ptr) {
        free_blocks_rm_node(free_blocks, block1->free_list_ptr);
        block1->free_list_ptr = NULL;
    }

    if (block2->free_list_ptr) {
        free_blocks_rm_node(free_blocks, block2->free_list_ptr);
        block2->free_list_ptr = NULL;
    }

    // update the size
    block1->size += block2->size;

    block_t *block_rm = coarse_ravl_rm(all_blocks, block2->data);
    assert(block_rm == block2);
    (void)block_rm; // WA for unused variable error
    umf_ba_global_free(block2);

    *merged_node = node1;

    return UMF_RESULT_SUCCESS;
}

// free_block_merge_with_prev - merge the given free block
// with the previous one if both are unused and have continuous data.
// Remove the merged block from the tree of free blocks.
static ravl_node_t *free_block_merge_with_prev(coarse_t *coarse,
                                               ravl_node_t *node) {
    ravl_node_t *node_prev = get_node_prev(node);
    if (!node_prev) {
        return node;
    }

    ravl_node_t *merged_node = NULL;
    umf_result_t umf_result =
        user_block_merge(coarse, node_prev, node, false, &merged_node);
    if (umf_result != UMF_RESULT_SUCCESS) {
        return node;
    }

    assert(merged_node != NULL);

    return merged_node;
}

// free_block_merge_with_next - merge the given free block
// with the next one if both are unused and have continuous data.
// Remove the merged block from the tree of free blocks.
static ravl_node_t *free_block_merge_with_next(coarse_t *coarse,
                                               ravl_node_t *node) {
    ravl_node_t *node_next = get_node_next(node);
    if (!node_next) {
        return node;
    }

    ravl_node_t *merged_node = NULL;
    umf_result_t umf_result =
        user_block_merge(coarse, node, node_next, false, &merged_node);
    if (umf_result != UMF_RESULT_SUCCESS) {
        return node;
    }

    assert(merged_node != NULL);

    return merged_node;
}

#ifndef NDEBUG // begin of DEBUG code

typedef struct debug_cb_args_t {
    coarse_t *provider;
    size_t sum_used;
    size_t sum_blocks_size;
    size_t num_all_blocks;
    size_t num_free_blocks;
} debug_cb_args_t;

static void debug_verify_all_blocks_cb(void *data, void *arg) {
    assert(data);
    assert(arg);

    ravl_data_t *node_data = data;
    block_t *block = node_data->value;
    assert(block);

    debug_cb_args_t *cb_args = (debug_cb_args_t *)arg;
    coarse_t *provider = cb_args->provider;

    ravl_node_t *node =
        ravl_find(provider->all_blocks, data, RAVL_PREDICATE_EQUAL);
    assert(node);

    block_t *block_next = get_block_next(node);
    block_t *block_prev = get_block_prev(node);

    cb_args->num_all_blocks++;
    if (!block->used) {
        cb_args->num_free_blocks++;
    }

    assert(block->data);
    assert(block->size > 0);

    // data addresses in the list are in ascending order
    if (block_prev) {
        assert(block_prev->data < block->data);
    }

    if (block_next) {
        assert(block->data < block_next->data);
    }

    // two block's data should not overlap
    if (block_next) {
        assert((block->data + block->size) <= block_next->data);
    }

    cb_args->sum_blocks_size += block->size;
    if (block->used) {
        cb_args->sum_used += block->size;
    }
}

static umf_result_t coarse_get_stats_no_lock(coarse_t *coarse,
                                             coarse_stats_t *stats);

static bool debug_check(coarse_t *provider) {
    assert(provider);

    coarse_stats_t stats = {0};
    coarse_get_stats_no_lock(provider, &stats);

    debug_cb_args_t cb_args = {0};
    cb_args.provider = provider;

    // verify the all_blocks list
    ravl_foreach(provider->all_blocks, debug_verify_all_blocks_cb, &cb_args);

    assert(cb_args.num_all_blocks == stats.num_all_blocks);
    assert(cb_args.num_free_blocks == stats.num_free_blocks);
    assert(cb_args.sum_used == provider->used_size);
    assert(cb_args.sum_blocks_size == provider->alloc_size);
    assert(provider->alloc_size >= provider->used_size);

    return true;
}
#endif /* NDEBUG */ // end of DEBUG code

static umf_result_t coarse_add_used_block(coarse_t *coarse, void *addr,
                                          size_t size) {
    block_t *new_block =
        coarse_ravl_add_new(coarse->all_blocks, addr, size, NULL);
    if (new_block == NULL) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    new_block->used = true;
    coarse->alloc_size += size;
    coarse->used_size += size;

    return UMF_RESULT_SUCCESS;
}

static void coarse_ravl_cb_rm_all_blocks_node(void *data, void *arg) {
    assert(data);
    assert(arg);

    coarse_t *coarse = (struct coarse_t *)arg;
    ravl_data_t *node_data = data;
    block_t *block = node_data->value;
    assert(block);

    if (block->used) {
#ifndef NDEBUG
        LOG_WARN("not freed block (addr: %p, size: %zu)", (void *)block->data,
                 block->size);
#endif
        assert(coarse->used_size >= block->size);
        coarse->used_size -= block->size;
    }

    if (block->free_list_ptr) {
        free_blocks_rm_node(coarse->free_blocks, block->free_list_ptr);
    }

    if (coarse->cb.free) {
        coarse->cb.free(coarse->provider, block->data, block->size);
    }

    assert(coarse->alloc_size >= block->size);
    coarse->alloc_size -= block->size;

    umf_ba_global_free(block);
}

static umf_result_t can_provider_split(coarse_t *coarse, void *ptr,
                                       size_t totalSize, size_t firstSize) {
    // check if the block can be split
    umf_result_t umf_result =
        coarse->cb.split(coarse->provider, ptr, totalSize, firstSize);
    if (umf_result != UMF_RESULT_SUCCESS) {
        LOG_ERR(
            "coarse_split_cb->(ptr=%p, totalSize = %zu = (%zu + %zu)) failed",
            ptr, totalSize, firstSize, totalSize - firstSize);
    }

    return umf_result;
}

static umf_result_t create_aligned_block(coarse_t *coarse, size_t orig_size,
                                         size_t alignment, block_t **current) {
    (void)orig_size; // unused in the Release version
    int rv;

    block_t *curr = *current;

    // In case of non-zero alignment create an aligned block what would be further used.
    uintptr_t orig_data = (uintptr_t)curr->data;
    uintptr_t aligned_data = ALIGN_UP(orig_data, alignment);
    size_t padding = aligned_data - orig_data;
    if (alignment > 0 && padding > 0) {
        // check if block can be split by the upstream provider
        umf_result_t umf_result =
            can_provider_split(coarse, curr->data, curr->size, padding);
        if (umf_result != UMF_RESULT_SUCCESS) {
            return umf_result;
        }

        block_t *aligned_block =
            coarse_ravl_add_new(coarse->all_blocks, curr->data + padding,
                                curr->size - padding, NULL);
        if (aligned_block == NULL) {
            return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        }

        curr->used = false;
        curr->size = padding;

        rv = free_blocks_add(coarse->free_blocks, curr);
        if (rv) {
            return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        }

        // use aligned block
        *current = aligned_block;
        assert((*current)->size >= orig_size);
    }

    return UMF_RESULT_SUCCESS;
}

// Split the current block and put the new block after the one that we use.
static umf_result_t split_current_block(coarse_t *coarse, block_t *curr,
                                        size_t size) {

    // check if block can be split by the upstream provider
    umf_result_t umf_result =
        can_provider_split(coarse, curr->data, curr->size, size);
    if (umf_result != UMF_RESULT_SUCCESS) {
        return umf_result;
    }

    ravl_node_t *new_node = NULL;

    block_t *new_block = coarse_ravl_add_new(
        coarse->all_blocks, curr->data + size, curr->size - size, &new_node);
    if (new_block == NULL) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    new_block->used = false;

    int rv = free_blocks_add(coarse->free_blocks, get_node_block(new_node));
    if (rv) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    return UMF_RESULT_SUCCESS;
}

static block_t *find_free_block(struct ravl *free_blocks, size_t size,
                                size_t alignment,
                                coarse_strategy_t allocation_strategy) {
    block_t *block;
    size_t new_size = size + alignment;

    switch (allocation_strategy) {
    case UMF_COARSE_MEMORY_STRATEGY_FASTEST:
        // Always allocate a free block of the (size + alignment) size
        // and later cut out the properly aligned part leaving two remaining parts.
        if (new_size < size) {
            LOG_ERR("arithmetic overflow (size + alignment)");
            return NULL;
        }

        return free_blocks_rm_ge(free_blocks, new_size, 0,
                                 CHECK_ONLY_THE_FIRST_BLOCK);

    case UMF_COARSE_MEMORY_STRATEGY_FASTEST_BUT_ONE:
        // First check if the first free block of the 'size' size has the correct alignment.
        block = free_blocks_rm_ge(free_blocks, size, alignment,
                                  CHECK_ONLY_THE_FIRST_BLOCK);
        if (block) {
            return block;
        }

        if (new_size < size) {
            LOG_ERR("arithmetic overflow (size + alignment)");
            return NULL;
        }

        // If not, use the `UMF_COARSE_MEMORY_STRATEGY_FASTEST` strategy.
        return free_blocks_rm_ge(free_blocks, new_size, 0,
                                 CHECK_ONLY_THE_FIRST_BLOCK);

    case UMF_COARSE_MEMORY_STRATEGY_CHECK_ALL_SIZE:
        // First look through all free blocks of the 'size' size
        // and choose the first one with the correct alignment.
        block = free_blocks_rm_ge(free_blocks, size, alignment,
                                  CHECK_ALL_BLOCKS_OF_SIZE);
        if (block) {
            return block;
        }

        if (new_size < size) {
            LOG_ERR("arithmetic overflow (size + alignment)");
            return NULL;
        }

        // If none of them had the correct alignment,
        // use the `UMF_COARSE_MEMORY_STRATEGY_FASTEST` strategy.
        return free_blocks_rm_ge(free_blocks, new_size, 0,
                                 CHECK_ONLY_THE_FIRST_BLOCK);
    }

    return NULL;
}

static int free_blocks_re_add(coarse_t *coarse, block_t *block) {
    assert(coarse);

    ravl_node_t *node = coarse_ravl_find_node(coarse->all_blocks, block->data);
    assert(node);

    // merge with prev and/or next block if they are unused and have continuous data
    node = free_block_merge_with_prev(coarse, node);
    node = free_block_merge_with_next(coarse, node);

    return free_blocks_add(coarse->free_blocks, get_node_block(node));
}

static void ravl_cb_count(void *data, void *arg) {
    assert(arg);
    (void)data; // unused

    size_t *num_all_blocks = arg;
    (*num_all_blocks)++;
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

    size_t *num_all_blocks = arg;
    while (free_block) {
        (*num_all_blocks)++;
        free_block = free_block->next;
    }
}

static umf_result_t coarse_get_stats_no_lock(coarse_t *coarse,
                                             coarse_stats_t *stats) {
    assert(coarse);

    size_t num_all_blocks = 0;
    ravl_foreach(coarse->all_blocks, ravl_cb_count, &num_all_blocks);

    size_t num_free_blocks = 0;
    ravl_foreach(coarse->free_blocks, ravl_cb_count_free, &num_free_blocks);

    stats->alloc_size = coarse->alloc_size;
    stats->used_size = coarse->used_size;
    stats->num_all_blocks = num_all_blocks;
    stats->num_free_blocks = num_free_blocks;

    return UMF_RESULT_SUCCESS;
}

// PUBLIC API

umf_result_t coarse_new(coarse_params_t *coarse_params, coarse_t **pcoarse) {
#ifdef _WIN32
    utils_init_once(&Log_initialized, utils_log_init);
#endif /* _WIN32 */

    if (coarse_params == NULL || pcoarse == NULL) {
        LOG_ERR("coarse parameters or handle is missing");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (!coarse_params->provider) {
        LOG_ERR("memory provider is not set");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (!coarse_params->page_size) {
        LOG_ERR("page size of the memory provider is not set");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (!coarse_params->cb.split) {
        LOG_ERR("coarse split callback is not set");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (!coarse_params->cb.merge) {
        LOG_ERR("coarse merge callback is not set");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    // alloc() and free() callbacks are optional

    coarse_t *coarse = umf_ba_global_alloc(sizeof(*coarse));
    if (!coarse) {
        LOG_ERR("out of the host memory");
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    memset(coarse, 0, sizeof(*coarse));

    coarse->provider = coarse_params->provider;
    coarse->page_size = coarse_params->page_size;
    coarse->cb = coarse_params->cb;
    coarse->allocation_strategy = coarse_params->allocation_strategy;

    umf_result_t umf_result = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;

    coarse->free_blocks = ravl_new_sized(coarse_ravl_comp, sizeof(ravl_data_t));
    if (coarse->free_blocks == NULL) {
        LOG_ERR("out of the host memory");
        goto err_free_coarse;
    }

    coarse->all_blocks = ravl_new_sized(coarse_ravl_comp, sizeof(ravl_data_t));
    if (coarse->all_blocks == NULL) {
        LOG_ERR("out of the host memory");
        goto err_delete_ravl_free_blocks;
    }

    coarse->alloc_size = 0;
    coarse->used_size = 0;

    umf_result = UMF_RESULT_ERROR_UNKNOWN;

    if (utils_mutex_init(&coarse->lock) == NULL) {
        LOG_ERR("lock initialization failed");
        goto err_delete_ravl_all_blocks;
    }

    assert(coarse->used_size == 0);
    assert(coarse->alloc_size == 0);
    assert(debug_check(coarse));

    *pcoarse = coarse;

    return UMF_RESULT_SUCCESS;

err_delete_ravl_all_blocks:
    ravl_delete(coarse->all_blocks);
err_delete_ravl_free_blocks:
    ravl_delete(coarse->free_blocks);
err_free_coarse:
    umf_ba_global_free(coarse);
    return umf_result;
}

void coarse_delete(coarse_t *coarse) {
    if (coarse == NULL) {
        LOG_ERR("coarse handle is missing");
        return;
    }

    utils_mutex_destroy_not_free(&coarse->lock);

    ravl_foreach(coarse->all_blocks, coarse_ravl_cb_rm_all_blocks_node, coarse);
    assert(coarse->used_size == 0);
    assert(coarse->alloc_size == 0);

    ravl_delete(coarse->all_blocks);
    ravl_delete(coarse->free_blocks);

    umf_ba_global_free(coarse);
}

umf_result_t coarse_add_memory_from_provider(coarse_t *coarse, size_t size) {
    umf_result_t umf_result;
    void *ptr = NULL;

    if (coarse == NULL || size == 0) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (!coarse->cb.alloc) {
        LOG_ERR("error: alloc callback is not set");
        return UMF_RESULT_ERROR_NOT_SUPPORTED;
    }

    umf_result = coarse_alloc(coarse, size, coarse->page_size, &ptr);
    if (umf_result != UMF_RESULT_SUCCESS) {
        return umf_result;
    }

    assert(ptr);

    return coarse_free(coarse, ptr, size);
}

umf_result_t coarse_add_memory_fixed(coarse_t *coarse, void *addr,
                                     size_t size) {
    umf_result_t umf_result;

    if (coarse == NULL || addr == NULL || size == 0) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (coarse->cb.alloc || coarse->cb.free) {
        LOG_ERR("error: alloc or free callback is set");
        return UMF_RESULT_ERROR_NOT_SUPPORTED;
    }

    if (utils_mutex_lock(&coarse->lock) != 0) {
        LOG_ERR("locking the lock failed");
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    assert(debug_check(coarse));

    umf_result = coarse_add_used_block(coarse, addr, size);

    assert(debug_check(coarse));
    utils_mutex_unlock(&coarse->lock);

    if (umf_result != UMF_RESULT_SUCCESS) {
        return umf_result;
    }

    umf_result = coarse_free(coarse, addr, size);
    if (umf_result != UMF_RESULT_SUCCESS) {
        return umf_result;
    }

    LOG_DEBUG("coarse_ALLOC (add_memory_block) %zu used %zu alloc %zu", size,
              coarse->used_size, coarse->alloc_size);

    return UMF_RESULT_SUCCESS;
}

umf_result_t coarse_alloc(coarse_t *coarse, size_t size, size_t alignment,
                          void **resultPtr) {
    umf_result_t umf_result = UMF_RESULT_ERROR_UNKNOWN;

    if (coarse == NULL || resultPtr == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    // alignment must be a power of two and a multiple or a divider of the page size
    if (alignment == 0) {
        alignment = coarse->page_size;
    } else if ((alignment & (alignment - 1)) ||
               ((alignment % coarse->page_size) &&
                (coarse->page_size % alignment))) {
        LOG_ERR("wrong alignment: %zu (not a power of 2 or a multiple or a "
                "divider of the page size (%zu))",
                alignment, coarse->page_size);
        return UMF_RESULT_ERROR_INVALID_ALIGNMENT;
    } else if (IS_NOT_ALIGNED(alignment, coarse->page_size)) {
        alignment = ALIGN_UP_SAFE(alignment, coarse->page_size);
    }

    if (utils_mutex_lock(&coarse->lock) != 0) {
        LOG_ERR("locking the lock failed");
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    assert(debug_check(coarse));

    // Find a block with greater or equal size using the given memory allocation strategy
    block_t *curr = find_free_block(coarse->free_blocks, size, alignment,
                                    coarse->allocation_strategy);

    // If the block that we want to reuse has a greater size, split it.
    // Try to merge the split part with the successor if it is not used.
    enum { ACTION_NONE = 0, ACTION_USE, ACTION_SPLIT } action = ACTION_NONE;

    if (curr && curr->size > size) {
        action = ACTION_SPLIT;
    } else if (curr && curr->size == size) {
        action = ACTION_USE;
    }

    if (action) { // ACTION_SPLIT or ACTION_USE
        assert(curr->used == false);

        // In case of non-zero alignment create an aligned block what would be further used.
        if (alignment > 0) {
            umf_result = create_aligned_block(coarse, size, alignment, &curr);
            if (umf_result != UMF_RESULT_SUCCESS) {
                (void)free_blocks_re_add(coarse, curr);
                goto err_unlock;
            }
        }

        if (action == ACTION_SPLIT) {
            // Split the current block and put the new block after the one that we use.
            umf_result = split_current_block(coarse, curr, size);
            if (umf_result != UMF_RESULT_SUCCESS) {
                (void)free_blocks_re_add(coarse, curr);
                goto err_unlock;
            }

            curr->size = size;

            LOG_DEBUG("coarse_ALLOC (split_block) %zu used %zu alloc %zu", size,
                      coarse->used_size, coarse->alloc_size);

        } else { // action == ACTION_USE
            LOG_DEBUG("coarse_ALLOC (same_block) %zu used %zu alloc %zu", size,
                      coarse->used_size, coarse->alloc_size);
        }

        curr->used = true;
        *resultPtr = curr->data;
        coarse->used_size += size;

        assert(debug_check(coarse));
        utils_mutex_unlock(&coarse->lock);

        return UMF_RESULT_SUCCESS;
    }

    // no suitable block found - try to get more memory from the upstream provider
    umf_result = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;

    *resultPtr = NULL;

    if (!coarse->cb.alloc) {
        LOG_ERR("out of memory");
        goto err_unlock;
    }

    umf_result = coarse->cb.alloc(coarse->provider, size, alignment, resultPtr);
    if (umf_result != UMF_RESULT_SUCCESS) {
        LOG_ERR("coarse_alloc_cb() failed: out of memory");
        goto err_unlock;
    }

    ASSERT_IS_ALIGNED(((uintptr_t)(*resultPtr)), alignment);

    umf_result = coarse_add_used_block(coarse, *resultPtr, size);
    if (umf_result != UMF_RESULT_SUCCESS) {
        if (coarse->cb.free) {
            coarse->cb.free(coarse->provider, *resultPtr, size);
        }
        goto err_unlock;
    }

    LOG_DEBUG("coarse_ALLOC (memory_provider) %zu used %zu alloc %zu", size,
              coarse->used_size, coarse->alloc_size);

    umf_result = UMF_RESULT_SUCCESS;

err_unlock:
    assert(debug_check(coarse));
    utils_mutex_unlock(&coarse->lock);

    return umf_result;
}

umf_result_t coarse_free(coarse_t *coarse, void *ptr, size_t bytes) {
    if (coarse == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (ptr == NULL) {
        return UMF_RESULT_SUCCESS;
    }

    if (utils_mutex_lock(&coarse->lock) != 0) {
        LOG_ERR("locking the lock failed");
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    assert(debug_check(coarse));

    ravl_node_t *node = coarse_ravl_find_node(coarse->all_blocks, ptr);
    if (node == NULL) {
        // the block was not found
        LOG_ERR("memory block not found (ptr = %p, size = %zu)", ptr, bytes);
        utils_mutex_unlock(&coarse->lock);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    block_t *block = get_node_block(node);
    if (!block->used) {
        LOG_ERR("double free");
        utils_mutex_unlock(&coarse->lock);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (bytes > 0 && bytes != block->size) {
        LOG_ERR("wrong size of allocation");
        utils_mutex_unlock(&coarse->lock);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    LOG_DEBUG("coarse_FREE (return_block_to_pool) %zu used %zu alloc %zu",
              block->size, coarse->used_size - block->size, coarse->alloc_size);

    assert(coarse->used_size >= block->size);
    coarse->used_size -= block->size;

    block->used = false;

    // Merge with prev and/or next block if they are unused and have continuous data.
    node = free_block_merge_with_prev(coarse, node);
    node = free_block_merge_with_next(coarse, node);

    int rv = free_blocks_add(coarse->free_blocks, get_node_block(node));
    if (rv) {
        utils_mutex_unlock(&coarse->lock);
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    assert(debug_check(coarse));
    utils_mutex_unlock(&coarse->lock);

    return UMF_RESULT_SUCCESS;
}

umf_result_t coarse_merge(coarse_t *coarse, void *lowPtr, void *highPtr,
                          size_t totalSize) {
    umf_result_t umf_result;

    if (coarse == NULL || lowPtr == NULL || highPtr == NULL || totalSize == 0 ||
        ((uintptr_t)highPtr <= (uintptr_t)lowPtr) ||
        ((uintptr_t)highPtr - (uintptr_t)lowPtr >= totalSize)) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (utils_mutex_lock(&coarse->lock) != 0) {
        LOG_ERR("locking the lock failed");
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    assert(debug_check(coarse));

    umf_result = UMF_RESULT_ERROR_INVALID_ARGUMENT;

    ravl_node_t *low_node = coarse_ravl_find_node(coarse->all_blocks, lowPtr);
    if (low_node == NULL) {
        LOG_ERR("the lowPtr memory block not found");
        goto err_mutex_unlock;
    }

    block_t *low_block = get_node_block(low_node);
    if (!low_block->used) {
        LOG_ERR("the lowPtr block is not allocated");
        goto err_mutex_unlock;
    }

    ravl_node_t *high_node = coarse_ravl_find_node(coarse->all_blocks, highPtr);
    if (high_node == NULL) {
        LOG_ERR("the highPtr memory block not found");
        goto err_mutex_unlock;
    }

    block_t *high_block = get_node_block(high_node);
    if (!high_block->used) {
        LOG_ERR("the highPtr block is not allocated");
        goto err_mutex_unlock;
    }

    if (get_node_next(low_node) != high_node ||
        ((uintptr_t)highPtr != ((uintptr_t)lowPtr + low_block->size))) {
        LOG_ERR("given allocations are not adjacent");
        goto err_mutex_unlock;
    }

    assert(get_node_prev(high_node) == low_node);

    if (low_block->size + high_block->size != totalSize) {
        LOG_ERR("wrong totalSize: %zu != %zu", totalSize,
                low_block->size + high_block->size);
        goto err_mutex_unlock;
    }

    ravl_node_t *merged_node = NULL;

    umf_result =
        user_block_merge(coarse, low_node, high_node, true, &merged_node);
    if (umf_result != UMF_RESULT_SUCCESS) {
        LOG_ERR("merging a block failed");
        goto err_mutex_unlock;
    }

    assert(merged_node == low_node);
    assert(low_block->size == totalSize);

    umf_result = UMF_RESULT_SUCCESS;

err_mutex_unlock:
    assert(debug_check(coarse));
    utils_mutex_unlock(&coarse->lock);

    return umf_result;
}

umf_result_t coarse_split(coarse_t *coarse, void *ptr, size_t totalSize,
                          size_t firstSize) {
    umf_result_t umf_result;

    if (coarse == NULL || ptr == NULL || (firstSize >= totalSize) ||
        firstSize == 0 || totalSize == 0) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (utils_mutex_lock(&coarse->lock) != 0) {
        LOG_ERR("locking the lock failed");
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    assert(debug_check(coarse));

    umf_result = UMF_RESULT_ERROR_INVALID_ARGUMENT;

    ravl_node_t *node = coarse_ravl_find_node(coarse->all_blocks, ptr);
    if (node == NULL) {
        LOG_ERR("memory block not found");
        goto err_mutex_unlock;
    }

    block_t *block = get_node_block(node);

    if (block->size != totalSize) {
        LOG_ERR("wrong totalSize: %zu != %zu", totalSize, block->size);
        goto err_mutex_unlock;
    }

    if (!block->used) {
        LOG_ERR("block is not allocated");
        goto err_mutex_unlock;
    }

    // check if block can be split by the memory provider
    umf_result = can_provider_split(coarse, ptr, totalSize, firstSize);
    if (umf_result != UMF_RESULT_SUCCESS) {
        LOG_ERR("memory provider cannot split a memory block");
        goto err_mutex_unlock;
    }

    umf_result = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;

    block_t *new_block =
        coarse_ravl_add_new(coarse->all_blocks, block->data + firstSize,
                            block->size - firstSize, NULL);
    if (new_block == NULL) {
        goto err_mutex_unlock;
    }

    block->size = firstSize;
    new_block->used = true;

    assert(new_block->size == (totalSize - firstSize));

    umf_result = UMF_RESULT_SUCCESS;

err_mutex_unlock:
    assert(debug_check(coarse));
    utils_mutex_unlock(&coarse->lock);

    return umf_result;
}

coarse_stats_t coarse_get_stats(coarse_t *coarse) {
    coarse_stats_t stats = {0};

    if (coarse == NULL) {
        return stats;
    }

    if (utils_mutex_lock(&coarse->lock) != 0) {
        LOG_ERR("locking the lock failed");
        return stats;
    }

    coarse_get_stats_no_lock(coarse, &stats);

    utils_mutex_unlock(&coarse->lock);

    return stats;
}
