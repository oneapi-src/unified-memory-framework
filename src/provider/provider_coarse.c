/*
 * Copyright (C) 2023-2024 Intel Corporation
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

#include <umf/providers/provider_coarse.h>

#include "base_alloc_global.h"
#include "memory_provider_internal.h"
#include "ravl.h"
#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_log.h"

#define COARSE_BASE_NAME "coarse"

#define IS_ORIGIN_OF_BLOCK(origin, block)                                      \
    (((uintptr_t)(block)->data >= (uintptr_t)(origin)->data) &&                \
     ((uintptr_t)(block)->data + (block)->size <=                              \
      (uintptr_t)(origin)->data + (origin)->size))

typedef struct coarse_memory_provider_t {
    umf_memory_provider_handle_t upstream_memory_provider;

    // destroy upstream_memory_provider in finalize()
    bool destroy_upstream_memory_provider;

    // memory allocation strategy
    coarse_memory_provider_strategy_t allocation_strategy;

    void *init_buffer;

    size_t used_size;
    size_t alloc_size;

    // upstream_blocks - tree of all blocks allocated from the upstream provider
    struct ravl *upstream_blocks;

    // all_blocks - tree of all blocks - sorted by an address of data
    struct ravl *all_blocks;

    // free_blocks - tree of free blocks - sorted by a size of data,
    // each node contains a pointer (ravl_free_blocks_head_t)
    // to the head of the list of free blocks of the same size
    struct ravl *free_blocks;

    struct utils_mutex_t lock;

    // Name of the provider with the upstream provider:
    // "coarse (<name_of_upstream_provider>)"
    // for example: "coarse (L0)"
    char *name;

    // Set to true if the free() operation of the upstream memory provider is not supported
    // (i.e. if (umfMemoryProviderFree(upstream_memory_provider, NULL, 0) == UMF_RESULT_ERROR_NOT_SUPPORTED)
    bool disable_upstream_provider_free;
} coarse_memory_provider_t;

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

static bool is_same_origin(struct ravl *upstream_blocks, block_t *block1,
                           block_t *block2) {
    ravl_data_t rdata1 = {(uintptr_t)block1->data, NULL};
    ravl_node_t *ravl_origin1 =
        ravl_find(upstream_blocks, &rdata1, RAVL_PREDICATE_LESS_EQUAL);
    assert(ravl_origin1);

    block_t *origin1 = get_node_block(ravl_origin1);
    assert(IS_ORIGIN_OF_BLOCK(origin1, block1));

    return (IS_ORIGIN_OF_BLOCK(origin1, block2));
}

// The functions "coarse_ravl_*" handle lists of blocks:
// - coarse_provider->all_blocks and coarse_provider->upstream_blocks
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
// the coarse_provider->free_blocks RAVL tree.
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

    if (!head_node->head) {
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

    struct block_t *block = node->block;
    block->free_list_ptr = NULL;
    umf_ba_global_free(node);

    return block;
}

// node_list_rm_first - remove the first free block from the list of free blocks of the same size only if it can be properly aligned
static block_t *node_list_rm_first(ravl_free_blocks_head_t *head_node,
                                   size_t alignment) {
    assert(head_node);

    if (!head_node->head) {
        return NULL;
    }

    ravl_free_blocks_elem_t *node = head_node->head;
    assert(node->prev == NULL);
    struct block_t *block = node->block;

    if (IS_NOT_ALIGNED(block->size, alignment)) {
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

    if (!head_node->head) {
        return NULL;
    }

    assert(((ravl_free_blocks_elem_t *)head_node->head)->prev == NULL);

    ravl_free_blocks_elem_t *node;
    for (node = head_node->head; node != NULL; node = node->next) {
        if (IS_ALIGNED(node->block->size, alignment)) {
            return node_list_rm(head_node, node);
        }
    }

    return NULL;
}

// The functions "free_blocks_*" handle the coarse_provider->free_blocks RAVL tree
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
        return -1;
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

    block_t *block;
    switch (check_blocks) {
    case CHECK_ONLY_THE_FIRST_BLOCK:
        block = node_list_rm_first(head_node, alignment);
        break;
    case CHECK_ALL_BLOCKS_OF_SIZE:
        block = node_list_rm_with_alignment(head_node, alignment);
        break;
    default:
        LOG_DEBUG("wrong value of check_blocks");
        block = NULL;
        assert(0);
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
// It is used during merging free blocks and destroying the coarse_provider->free_blocks tree.
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
static umf_result_t user_block_merge(coarse_memory_provider_t *coarse_provider,
                                     ravl_node_t *node1, ravl_node_t *node2,
                                     bool used, ravl_node_t **merged_node) {
    assert(node1);
    assert(node2);
    assert(node1 == get_node_prev(node2));
    assert(node2 == get_node_next(node1));
    assert(merged_node);

    *merged_node = NULL;

    struct ravl *upstream_blocks = coarse_provider->upstream_blocks;
    struct ravl *all_blocks = coarse_provider->all_blocks;
    struct ravl *free_blocks = coarse_provider->free_blocks;

    block_t *block1 = get_node_block(node1);
    block_t *block2 = get_node_block(node2);
    assert(block1->data < block2->data);

    bool same_used = ((block1->used == used) && (block2->used == used));
    bool contignous_data = (block1->data + block1->size == block2->data);
    bool same_origin = is_same_origin(upstream_blocks, block1, block2);

    // check if blocks can be merged
    if (!same_used || !contignous_data || !same_origin) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
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
static ravl_node_t *
free_block_merge_with_prev(coarse_memory_provider_t *coarse_provider,
                           ravl_node_t *node) {
    ravl_node_t *node_prev = get_node_prev(node);
    if (!node_prev) {
        return node;
    }

    ravl_node_t *merged_node = NULL;
    umf_result_t umf_result =
        user_block_merge(coarse_provider, node_prev, node, false, &merged_node);
    if (umf_result != UMF_RESULT_SUCCESS) {
        return node;
    }

    assert(merged_node != NULL);

    return merged_node;
}

// free_block_merge_with_next - merge the given free block
// with the next one if both are unused and have continuous data.
// Remove the merged block from the tree of free blocks.
static ravl_node_t *
free_block_merge_with_next(coarse_memory_provider_t *coarse_provider,
                           ravl_node_t *node) {
    ravl_node_t *node_next = get_node_next(node);
    if (!node_next) {
        return node;
    }

    ravl_node_t *merged_node = NULL;
    umf_result_t umf_result =
        user_block_merge(coarse_provider, node, node_next, false, &merged_node);
    if (umf_result != UMF_RESULT_SUCCESS) {
        return node;
    }

    assert(merged_node != NULL);

    return merged_node;
}

// upstream_block_merge - merge the given two upstream blocks
static umf_result_t
upstream_block_merge(coarse_memory_provider_t *coarse_provider,
                     ravl_node_t *node1, ravl_node_t *node2,
                     ravl_node_t **merged_node) {
    assert(node1);
    assert(node2);
    assert(merged_node);

    *merged_node = NULL;

    umf_memory_provider_handle_t upstream_provider =
        coarse_provider->upstream_memory_provider;
    if (!upstream_provider) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    block_t *block1 = get_node_block(node1);
    block_t *block2 = get_node_block(node2);
    assert(block1->data < block2->data);

    bool contignous_data = (block1->data + block1->size == block2->data);
    if (!contignous_data) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    // check if blocks can be merged by the upstream provider
    umf_result_t merge_status = umfMemoryProviderAllocationMerge(
        coarse_provider->upstream_memory_provider, block1->data, block2->data,
        block1->size + block2->size);
    if (merge_status != UMF_RESULT_SUCCESS) {
        return merge_status;
    }

    // update the size
    block1->size += block2->size;

    struct ravl *upstream_blocks = coarse_provider->upstream_blocks;
    block_t *block_rm = coarse_ravl_rm(upstream_blocks, block2->data);
    assert(block_rm == block2);
    (void)block_rm; // WA for unused variable error
    umf_ba_global_free(block2);

    *merged_node = node1;

    return UMF_RESULT_SUCCESS;
}

// upstream_block_merge_with_prev - merge the given upstream block
// with the previous one if both have continuous data.
// Remove the merged block from the tree of upstream blocks.
static ravl_node_t *
upstream_block_merge_with_prev(coarse_memory_provider_t *coarse_provider,
                               ravl_node_t *node) {
    assert(node);

    ravl_node_t *node_prev = get_node_prev(node);
    if (!node_prev) {
        return node;
    }

    ravl_node_t *merged_node = NULL;
    umf_result_t umf_result =
        upstream_block_merge(coarse_provider, node_prev, node, &merged_node);
    if (umf_result != UMF_RESULT_SUCCESS) {
        return node;
    }

    assert(merged_node != NULL);

    return merged_node;
}

// upstream_block_merge_with_next - merge the given upstream block
// with the next one if both have continuous data.
// Remove the merged block from the tree of upstream blocks.
static ravl_node_t *
upstream_block_merge_with_next(coarse_memory_provider_t *coarse_provider,
                               ravl_node_t *node) {
    assert(node);

    ravl_node_t *node_next = get_node_next(node);
    if (!node_next) {
        return node;
    }

    ravl_node_t *merged_node = NULL;
    umf_result_t umf_result =
        upstream_block_merge(coarse_provider, node, node_next, &merged_node);
    if (umf_result != UMF_RESULT_SUCCESS) {
        return node;
    }

    assert(merged_node != NULL);

    return merged_node;
}

#ifndef NDEBUG // begin of DEBUG code

typedef struct debug_cb_args_t {
    coarse_memory_provider_t *provider;
    size_t sum_used;
    size_t sum_blocks_size;
    size_t num_all_blocks;
    size_t num_free_blocks;
    size_t num_alloc_blocks;
    size_t sum_alloc_size;
} debug_cb_args_t;

static void debug_verify_all_blocks_cb(void *data, void *arg) {
    assert(data);
    assert(arg);

    ravl_data_t *node_data = data;
    block_t *block = node_data->value;
    assert(block);

    debug_cb_args_t *cb_args = (debug_cb_args_t *)arg;
    coarse_memory_provider_t *provider = cb_args->provider;

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

    // There shouldn't be two adjacent unused blocks
    // if they are continuous and have the same origin.
    if (block_prev && !block_prev->used && !block->used &&
        (block_prev->data + block_prev->size == block->data)) {
        assert(!is_same_origin(provider->upstream_blocks, block_prev, block));
    }

    if (block_next && !block_next->used && !block->used &&
        (block->data + block->size == block_next->data)) {
        assert(!is_same_origin(provider->upstream_blocks, block, block_next));
    }

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

static void debug_verify_upstream_blocks_cb(void *data, void *arg) {
    assert(data);
    assert(arg);

    ravl_data_t *node_data = data;
    block_t *alloc = node_data->value;
    assert(alloc);

    debug_cb_args_t *cb_args = (debug_cb_args_t *)arg;
    coarse_memory_provider_t *provider = cb_args->provider;

    ravl_node_t *node =
        ravl_find(provider->upstream_blocks, data, RAVL_PREDICATE_EQUAL);
    assert(node);

    block_t *alloc_next = get_block_next(node);
    block_t *alloc_prev = get_block_prev(node);

    cb_args->num_alloc_blocks++;
    cb_args->sum_alloc_size += alloc->size;

    assert(alloc->data);
    assert(alloc->size > 0);

    // data addresses in the list are in ascending order
    if (alloc_prev) {
        assert(alloc_prev->data < alloc->data);
    }

    if (alloc_next) {
        assert(alloc->data < alloc_next->data);
    }

    // data should not overlap
    if (alloc_next) {
        assert((alloc->data + alloc->size) <= alloc_next->data);
    }
}

static umf_result_t
coarse_memory_provider_get_stats(void *provider,
                                 coarse_memory_provider_stats_t *stats);

static bool debug_check(coarse_memory_provider_t *provider) {
    assert(provider);

    coarse_memory_provider_stats_t stats = {0};
    coarse_memory_provider_get_stats(provider, &stats);

    debug_cb_args_t cb_args = {0};
    cb_args.provider = provider;

    // verify the all_blocks list
    ravl_foreach(provider->all_blocks, debug_verify_all_blocks_cb, &cb_args);

    assert(cb_args.num_all_blocks == stats.num_all_blocks);
    assert(cb_args.num_free_blocks == stats.num_free_blocks);
    assert(cb_args.sum_used == provider->used_size);
    assert(cb_args.sum_blocks_size == provider->alloc_size);
    assert(provider->alloc_size >= provider->used_size);

    // verify the upstream_blocks list
    ravl_foreach(provider->upstream_blocks, debug_verify_upstream_blocks_cb,
                 &cb_args);

    assert(cb_args.sum_alloc_size == provider->alloc_size);
    assert(cb_args.num_alloc_blocks == stats.num_upstream_blocks);

    return true;
}
#endif /* NDEBUG */ // end of DEBUG code

static umf_result_t
coarse_add_upstream_block(coarse_memory_provider_t *coarse_provider, void *addr,
                          size_t size) {
    ravl_node_t *alloc_node = NULL;

    block_t *alloc = coarse_ravl_add_new(coarse_provider->upstream_blocks, addr,
                                         size, &alloc_node);
    if (alloc == NULL) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    block_t *new_block =
        coarse_ravl_add_new(coarse_provider->all_blocks, addr, size, NULL);
    if (new_block == NULL) {
        coarse_ravl_rm(coarse_provider->upstream_blocks, addr);
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    // check if the new upstream block can be merged with its neighbours
    alloc_node = upstream_block_merge_with_prev(coarse_provider, alloc_node);
    alloc_node = upstream_block_merge_with_next(coarse_provider, alloc_node);

    new_block->used = true;
    coarse_provider->alloc_size += size;
    coarse_provider->used_size += size;

    return UMF_RESULT_SUCCESS;
}

static umf_result_t
coarse_memory_provider_set_name(coarse_memory_provider_t *coarse_provider) {
    if (coarse_provider->upstream_memory_provider == NULL) {
        // COARSE_BASE_NAME will be used
        coarse_provider->name = NULL;
        return UMF_RESULT_SUCCESS;
    }

    const char *up_name =
        umfMemoryProviderGetName(coarse_provider->upstream_memory_provider);
    if (!up_name) {
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    size_t length =
        strlen(COARSE_BASE_NAME) + strlen(up_name) + 3; // + 3 for " ()"

    coarse_provider->name = umf_ba_global_alloc(length + 1); // + 1 for '\0'
    if (coarse_provider->name == NULL) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    sprintf(coarse_provider->name, "%s (%s)", COARSE_BASE_NAME, up_name);

    return UMF_RESULT_SUCCESS;
}

// needed for coarse_memory_provider_initialize()
static umf_result_t coarse_memory_provider_alloc(void *provider, size_t size,
                                                 size_t alignment,
                                                 void **resultPtr);

// needed for coarse_memory_provider_initialize()
static umf_result_t coarse_memory_provider_free(void *provider, void *ptr,
                                                size_t bytes);

static umf_result_t coarse_memory_provider_initialize(void *params,
                                                      void **provider) {
    umf_result_t umf_result = UMF_RESULT_ERROR_UNKNOWN;

    if (provider == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (params == NULL) {
        LOG_ERR("coarse provider parameters are missing");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    coarse_memory_provider_params_t *coarse_params =
        (coarse_memory_provider_params_t *)params;

    // check params
    if (!coarse_params->upstream_memory_provider ==
        !coarse_params->init_buffer) {
        LOG_ERR("either upstream provider or init buffer has to be provided in "
                "the parameters (exactly one of them)");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (coarse_params->init_buffer_size == 0 &&
        (coarse_params->immediate_init_from_upstream ||
         coarse_params->init_buffer != NULL)) {
        LOG_ERR("init_buffer_size has to be greater than 0 if "
                "immediate_init_from_upstream or init_buffer is set");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (coarse_params->init_buffer_size != 0 &&
        (!coarse_params->immediate_init_from_upstream &&
         coarse_params->init_buffer == NULL)) {
        LOG_ERR("init_buffer_size is greater than 0 but none of "
                "immediate_init_from_upstream nor init_buffer is set");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (coarse_params->destroy_upstream_memory_provider &&
        !coarse_params->upstream_memory_provider) {
        LOG_ERR("destroy_upstream_memory_provider is true, but an upstream "
                "provider is not provided");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    coarse_memory_provider_t *coarse_provider =
        umf_ba_global_alloc(sizeof(*coarse_provider));
    if (!coarse_provider) {
        LOG_ERR("out of the host memory");
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    memset(coarse_provider, 0, sizeof(*coarse_provider));

    coarse_provider->upstream_memory_provider =
        coarse_params->upstream_memory_provider;
    coarse_provider->destroy_upstream_memory_provider =
        coarse_params->destroy_upstream_memory_provider;
    coarse_provider->allocation_strategy = coarse_params->allocation_strategy;
    coarse_provider->init_buffer = coarse_params->init_buffer;

    if (coarse_provider->upstream_memory_provider) {
        coarse_provider->disable_upstream_provider_free =
            umfIsFreeOpDefault(coarse_provider->upstream_memory_provider);
    } else {
        coarse_provider->disable_upstream_provider_free = false;
    }

    umf_result = coarse_memory_provider_set_name(coarse_provider);
    if (umf_result != UMF_RESULT_SUCCESS) {
        LOG_ERR("name initialization failed");
        goto err_free_coarse_provider;
    }

    coarse_provider->upstream_blocks =
        ravl_new_sized(coarse_ravl_comp, sizeof(ravl_data_t));
    if (coarse_provider->upstream_blocks == NULL) {
        LOG_ERR("out of the host memory");
        umf_result = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        goto err_free_name;
    }

    coarse_provider->free_blocks =
        ravl_new_sized(coarse_ravl_comp, sizeof(ravl_data_t));
    if (coarse_provider->free_blocks == NULL) {
        LOG_ERR("out of the host memory");
        umf_result = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        goto err_delete_ravl_upstream_blocks;
    }

    coarse_provider->all_blocks =
        ravl_new_sized(coarse_ravl_comp, sizeof(ravl_data_t));
    if (coarse_provider->all_blocks == NULL) {
        LOG_ERR("out of the host memory");
        umf_result = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        goto err_delete_ravl_free_blocks;
    }

    coarse_provider->alloc_size = 0;
    coarse_provider->used_size = 0;

    if (utils_mutex_init(&coarse_provider->lock) == NULL) {
        LOG_ERR("lock initialization failed");
        goto err_delete_ravl_all_blocks;
    }

    if (coarse_params->upstream_memory_provider &&
        coarse_params->immediate_init_from_upstream) {
        // allocate and immediately deallocate memory using the upstream provider
        void *init_buffer = NULL;
        coarse_memory_provider_alloc(
            coarse_provider, coarse_params->init_buffer_size, 0, &init_buffer);
        if (init_buffer == NULL) {
            umf_result = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
            goto err_destroy_mutex;
        }

        coarse_memory_provider_free(coarse_provider, init_buffer,
                                    coarse_params->init_buffer_size);

    } else if (coarse_params->init_buffer) {
        umf_result = coarse_add_upstream_block(coarse_provider,
                                               coarse_provider->init_buffer,
                                               coarse_params->init_buffer_size);
        if (umf_result != UMF_RESULT_SUCCESS) {
            goto err_destroy_mutex;
        }

        LOG_DEBUG("coarse_ALLOC (init_buffer) %zu used %zu alloc %zu",
                  coarse_params->init_buffer_size, coarse_provider->used_size,
                  coarse_provider->alloc_size);

        coarse_memory_provider_free(coarse_provider,
                                    coarse_provider->init_buffer,
                                    coarse_params->init_buffer_size);
    }

    assert(coarse_provider->used_size == 0);
    assert(coarse_provider->alloc_size == coarse_params->init_buffer_size);
    assert(debug_check(coarse_provider));

    *provider = coarse_provider;

    return UMF_RESULT_SUCCESS;

err_destroy_mutex:
    utils_mutex_destroy_not_free(&coarse_provider->lock);
err_delete_ravl_all_blocks:
    ravl_delete(coarse_provider->all_blocks);
err_delete_ravl_free_blocks:
    ravl_delete(coarse_provider->free_blocks);
err_delete_ravl_upstream_blocks:
    ravl_delete(coarse_provider->upstream_blocks);
err_free_name:
    umf_ba_global_free(coarse_provider->name);
err_free_coarse_provider:
    umf_ba_global_free(coarse_provider);
    return umf_result;
}

static void coarse_ravl_cb_rm_upstream_blocks_node(void *data, void *arg) {
    assert(data);
    assert(arg);

    coarse_memory_provider_t *coarse_provider =
        (struct coarse_memory_provider_t *)arg;
    ravl_data_t *node_data = data;
    block_t *alloc = node_data->value;
    assert(alloc);

    if (coarse_provider->upstream_memory_provider &&
        !coarse_provider->disable_upstream_provider_free) {
        // We continue to deallocate alloc blocks even if the upstream provider doesn't return success.
        umfMemoryProviderFree(coarse_provider->upstream_memory_provider,
                              alloc->data, alloc->size);
    }

    assert(coarse_provider->alloc_size >= alloc->size);
    coarse_provider->alloc_size -= alloc->size;

    umf_ba_global_free(alloc);
}

static void coarse_ravl_cb_rm_all_blocks_node(void *data, void *arg) {
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

    umf_ba_global_free(block);
}

static void coarse_memory_provider_finalize(void *provider) {
    if (provider == NULL) {
        assert(0);
        return;
    }

    coarse_memory_provider_t *coarse_provider =
        (struct coarse_memory_provider_t *)provider;

    utils_mutex_destroy_not_free(&coarse_provider->lock);

    ravl_foreach(coarse_provider->all_blocks, coarse_ravl_cb_rm_all_blocks_node,
                 coarse_provider);
    assert(coarse_provider->used_size == 0);

    ravl_foreach(coarse_provider->upstream_blocks,
                 coarse_ravl_cb_rm_upstream_blocks_node, coarse_provider);
    assert(coarse_provider->alloc_size == 0);

    ravl_delete(coarse_provider->upstream_blocks);
    ravl_delete(coarse_provider->all_blocks);
    ravl_delete(coarse_provider->free_blocks);

    umf_ba_global_free(coarse_provider->name);

    if (coarse_provider->destroy_upstream_memory_provider &&
        coarse_provider->upstream_memory_provider) {
        umfMemoryProviderDestroy(coarse_provider->upstream_memory_provider);
    }

    umf_ba_global_free(coarse_provider);
}

static umf_result_t
create_aligned_block(coarse_memory_provider_t *coarse_provider,
                     size_t orig_size, size_t alignment, block_t **current) {
    (void)orig_size; // unused in the Release version
    int rv;

    block_t *curr = *current;

    // In case of non-zero alignment create an aligned block what would be further used.
    uintptr_t orig_data = (uintptr_t)curr->data;
    uintptr_t aligned_data = ALIGN_UP(orig_data, alignment);
    size_t padding = aligned_data - orig_data;
    if (alignment > 0 && padding > 0) {
        block_t *aligned_block = coarse_ravl_add_new(
            coarse_provider->all_blocks, curr->data + padding,
            curr->size - padding, NULL);
        if (aligned_block == NULL) {
            return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        }

        curr->used = false;
        curr->size = padding;

        rv = free_blocks_add(coarse_provider->free_blocks, curr);
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
static umf_result_t
split_current_block(coarse_memory_provider_t *coarse_provider, block_t *curr,
                    size_t size) {
    ravl_node_t *new_node = NULL;

    block_t *new_block =
        coarse_ravl_add_new(coarse_provider->all_blocks, curr->data + size,
                            curr->size - size, &new_node);
    if (new_block == NULL) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    new_block->used = false;

    int rv =
        free_blocks_add(coarse_provider->free_blocks, get_node_block(new_node));
    if (rv) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    return UMF_RESULT_SUCCESS;
}

static block_t *
find_free_block(struct ravl *free_blocks, size_t size, size_t alignment,
                coarse_memory_provider_strategy_t allocation_strategy) {
    block_t *block;

    switch (allocation_strategy) {
    case UMF_COARSE_MEMORY_STRATEGY_FASTEST:
        // Always allocate a free block of the (size + alignment) size
        // and later cut out the properly aligned part leaving two remaining parts.
        return free_blocks_rm_ge(free_blocks, size + alignment, 0,
                                 CHECK_ONLY_THE_FIRST_BLOCK);

    case UMF_COARSE_MEMORY_STRATEGY_FASTEST_BUT_ONE:
        // First check if the first free block of the 'size' size has the correct alignment.
        block = free_blocks_rm_ge(free_blocks, size, alignment,
                                  CHECK_ONLY_THE_FIRST_BLOCK);
        if (block) {
            return block;
        }

        // If not, use the `UMF_COARSE_MEMORY_STRATEGY_FASTEST` strategy.
        return free_blocks_rm_ge(free_blocks, size + alignment, 0,
                                 CHECK_ONLY_THE_FIRST_BLOCK);

    case UMF_COARSE_MEMORY_STRATEGY_CHECK_ALL_SIZE:
        // First look through all free blocks of the 'size' size
        // and choose the first one with the correct alignment.
        block = free_blocks_rm_ge(free_blocks, size, alignment,
                                  CHECK_ALL_BLOCKS_OF_SIZE);
        if (block) {
            return block;
        }

        // If none of them had the correct alignment,
        // use the `UMF_COARSE_MEMORY_STRATEGY_FASTEST` strategy.
        return free_blocks_rm_ge(free_blocks, size + alignment, 0,
                                 CHECK_ONLY_THE_FIRST_BLOCK);

    default:
        LOG_ERR("unknown memory allocation strategy");
        assert(0);
        return NULL;
    }
}

static umf_result_t coarse_memory_provider_alloc(void *provider, size_t size,
                                                 size_t alignment,
                                                 void **resultPtr) {
    umf_result_t umf_result = UMF_RESULT_SUCCESS;

    if (provider == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (resultPtr == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    coarse_memory_provider_t *coarse_provider =
        (struct coarse_memory_provider_t *)provider;

    if (utils_mutex_lock(&coarse_provider->lock) != 0) {
        LOG_ERR("locking the lock failed");
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    assert(debug_check(coarse_provider));

    // Find a block with greater or equal size using the given memory allocation strategy
    block_t *curr =
        find_free_block(coarse_provider->free_blocks, size, alignment,
                        coarse_provider->allocation_strategy);

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
            umf_result =
                create_aligned_block(coarse_provider, size, alignment, &curr);
            if (umf_result != UMF_RESULT_SUCCESS) {
                if (utils_mutex_unlock(&coarse_provider->lock) != 0) {
                    LOG_ERR("unlocking the lock failed");
                }
                return umf_result;
            }
        }

        if (action == ACTION_SPLIT) {
            // Split the current block and put the new block after the one that we use.
            umf_result = split_current_block(coarse_provider, curr, size);
            if (umf_result != UMF_RESULT_SUCCESS) {
                if (utils_mutex_unlock(&coarse_provider->lock) != 0) {
                    LOG_ERR("unlocking the lock failed");
                }
                return umf_result;
            }

            curr->size = size;

            LOG_DEBUG("coarse_ALLOC (split_block) %zu used %zu alloc %zu", size,
                      coarse_provider->used_size, coarse_provider->alloc_size);

        } else { // action == ACTION_USE
            LOG_DEBUG("coarse_ALLOC (same_block) %zu used %zu alloc %zu", size,
                      coarse_provider->used_size, coarse_provider->alloc_size);
        }

        curr->used = true;
        *resultPtr = curr->data;
        coarse_provider->used_size += size;

        assert(debug_check(coarse_provider));

        if (utils_mutex_unlock(&coarse_provider->lock) != 0) {
            LOG_ERR("unlocking the lock failed");
            return UMF_RESULT_ERROR_UNKNOWN;
        }

        return UMF_RESULT_SUCCESS;
    }

    // no suitable block found - try to get more memory from the upstream provider

    if (coarse_provider->upstream_memory_provider == NULL) {
        LOG_ERR("out of memory - no upstream memory provider given");
        umf_result = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        goto err_unlock;
    }

    umfMemoryProviderAlloc(coarse_provider->upstream_memory_provider, size,
                           alignment, resultPtr);
    if (*resultPtr == NULL) {
        LOG_ERR("out of memory - upstream memory provider allocation failed");
        umf_result = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        goto err_unlock;
    }

    ASSERT_IS_ALIGNED(((uintptr_t)(*resultPtr)), alignment);

    umf_result = coarse_add_upstream_block(coarse_provider, *resultPtr, size);
    if (umf_result != UMF_RESULT_SUCCESS) {
        if (!coarse_provider->disable_upstream_provider_free) {
            umfMemoryProviderFree(coarse_provider->upstream_memory_provider,
                                  *resultPtr, size);
        }
        goto err_unlock;
    }

    LOG_DEBUG("coarse_ALLOC (upstream) %zu used %zu alloc %zu", size,
              coarse_provider->used_size, coarse_provider->alloc_size);

    umf_result = UMF_RESULT_SUCCESS;

err_unlock:
    assert(debug_check(coarse_provider));

    if (utils_mutex_unlock(&coarse_provider->lock) != 0) {
        LOG_ERR("unlocking the lock failed");
        if (umf_result == UMF_RESULT_SUCCESS) {
            umf_result = UMF_RESULT_ERROR_UNKNOWN;
        }
    }

    return umf_result;
}

static umf_result_t coarse_memory_provider_free(void *provider, void *ptr,
                                                size_t bytes) {
    if (provider == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    coarse_memory_provider_t *coarse_provider =
        (struct coarse_memory_provider_t *)provider;

    if (utils_mutex_lock(&coarse_provider->lock) != 0) {
        LOG_ERR("locking the lock failed");
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    assert(debug_check(coarse_provider));

    ravl_node_t *node = coarse_ravl_find_node(coarse_provider->all_blocks, ptr);
    if (node == NULL) {
        // the block was not found
        utils_mutex_unlock(&coarse_provider->lock);
        LOG_ERR("memory block not found (ptr = %p, size = %zu)", ptr, bytes);
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    block_t *block = get_node_block(node);
    if (!block->used) {
        // the block is already free
        utils_mutex_unlock(&coarse_provider->lock);
        LOG_ERR("the block is already free");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (bytes > 0 && bytes != block->size) {
        // wrong size of allocation
        utils_mutex_unlock(&coarse_provider->lock);
        LOG_ERR("wrong size of allocation");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    LOG_DEBUG("coarse_FREE (return_block_to_pool) %zu used %zu alloc %zu",
              block->size, coarse_provider->used_size - block->size,
              coarse_provider->alloc_size);

    assert(coarse_provider->used_size >= block->size);
    coarse_provider->used_size -= block->size;

    block->used = false;

    // Merge with prev and/or next block if they are unused and have continuous data.
    node = free_block_merge_with_prev(coarse_provider, node);
    node = free_block_merge_with_next(coarse_provider, node);

    int rv =
        free_blocks_add(coarse_provider->free_blocks, get_node_block(node));
    if (rv) {
        utils_mutex_unlock(&coarse_provider->lock);
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    assert(debug_check(coarse_provider));

    if (utils_mutex_unlock(&coarse_provider->lock) != 0) {
        LOG_ERR("unlocking the lock failed");
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    return UMF_RESULT_SUCCESS;
}

static void coarse_memory_provider_get_last_native_error(void *provider,
                                                         const char **ppMessage,
                                                         int32_t *pError) {
    (void)provider; // unused

    if (ppMessage == NULL || pError == NULL) {
        assert(0);
        return;
    }

    // Nothing more is needed here, since
    // there is no UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC error used.
}

static umf_result_t coarse_memory_provider_get_min_page_size(void *provider,
                                                             void *ptr,
                                                             size_t *pageSize) {
    if (provider == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    coarse_memory_provider_t *coarse_provider =
        (struct coarse_memory_provider_t *)provider;

    if (!coarse_provider->upstream_memory_provider) {
        *pageSize = utils_get_page_size();
        return UMF_RESULT_SUCCESS;
    }

    return umfMemoryProviderGetMinPageSize(
        coarse_provider->upstream_memory_provider, ptr, pageSize);
}

static umf_result_t
coarse_memory_provider_get_recommended_page_size(void *provider, size_t size,
                                                 size_t *pageSize) {
    if (provider == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    coarse_memory_provider_t *coarse_provider =
        (struct coarse_memory_provider_t *)provider;

    if (!coarse_provider->upstream_memory_provider) {
        *pageSize = utils_get_page_size();
        return UMF_RESULT_SUCCESS;
    }

    return umfMemoryProviderGetRecommendedPageSize(
        coarse_provider->upstream_memory_provider, size, pageSize);
}

static const char *coarse_memory_provider_get_name(void *provider) {
    if (provider == NULL) {
        return COARSE_BASE_NAME;
    }

    coarse_memory_provider_t *coarse_provider =
        (struct coarse_memory_provider_t *)provider;

    if (!coarse_provider->name) {
        return COARSE_BASE_NAME;
    }

    return coarse_provider->name;
}

static void ravl_cb_count(void *data, void *arg) {
    assert(arg);
    (void)data; /* unused */

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

static umf_result_t
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
    size_t num_upstream_blocks = 0;
    ravl_foreach(coarse_provider->upstream_blocks, ravl_cb_count,
                 &num_upstream_blocks);

    size_t num_all_blocks = 0;
    ravl_foreach(coarse_provider->all_blocks, ravl_cb_count, &num_all_blocks);

    size_t num_free_blocks = 0;
    ravl_foreach(coarse_provider->free_blocks, ravl_cb_count_free,
                 &num_free_blocks);

    stats->alloc_size = coarse_provider->alloc_size;
    stats->used_size = coarse_provider->used_size;
    stats->num_upstream_blocks = num_upstream_blocks;
    stats->num_all_blocks = num_all_blocks;
    stats->num_free_blocks = num_free_blocks;

    return UMF_RESULT_SUCCESS;
}

static umf_result_t coarse_memory_provider_purge_lazy(void *provider, void *ptr,
                                                      size_t size) {
    if (provider == NULL || ptr == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    coarse_memory_provider_t *coarse_provider =
        (struct coarse_memory_provider_t *)provider;
    if (coarse_provider->upstream_memory_provider == NULL) {
        LOG_ERR("no upstream memory provider given");
        return UMF_RESULT_ERROR_NOT_SUPPORTED;
    }

    return umfMemoryProviderPurgeLazy(coarse_provider->upstream_memory_provider,
                                      ptr, size);
}

static umf_result_t coarse_memory_provider_purge_force(void *provider,
                                                       void *ptr, size_t size) {
    if (provider == NULL || ptr == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    coarse_memory_provider_t *coarse_provider =
        (struct coarse_memory_provider_t *)provider;
    if (coarse_provider->upstream_memory_provider == NULL) {
        LOG_ERR("no upstream memory provider given");
        return UMF_RESULT_ERROR_NOT_SUPPORTED;
    }

    return umfMemoryProviderPurgeForce(
        coarse_provider->upstream_memory_provider, ptr, size);
}

static umf_result_t coarse_memory_provider_allocation_split(void *provider,
                                                            void *ptr,
                                                            size_t totalSize,
                                                            size_t firstSize) {
    if (provider == NULL || ptr == NULL || (firstSize >= totalSize) ||
        firstSize == 0) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_result_t umf_result;

    coarse_memory_provider_t *coarse_provider =
        (struct coarse_memory_provider_t *)provider;

    if (utils_mutex_lock(&coarse_provider->lock) != 0) {
        LOG_ERR("locking the lock failed");
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    assert(debug_check(coarse_provider));

    ravl_node_t *node = coarse_ravl_find_node(coarse_provider->all_blocks, ptr);
    if (node == NULL) {
        LOG_ERR("memory block not found");
        umf_result = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err_mutex_unlock;
    }

    block_t *block = get_node_block(node);

    if (block->size != totalSize) {
        LOG_ERR("wrong totalSize");
        umf_result = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err_mutex_unlock;
    }

    if (!block->used) {
        LOG_ERR("block is not allocated");
        umf_result = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err_mutex_unlock;
    }

    block_t *new_block = coarse_ravl_add_new(coarse_provider->all_blocks,
                                             block->data + firstSize,
                                             block->size - firstSize, NULL);
    if (new_block == NULL) {
        umf_result = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        goto err_mutex_unlock;
    }

    block->size = firstSize;
    new_block->used = true;

    assert(new_block->size == (totalSize - firstSize));

    umf_result = UMF_RESULT_SUCCESS;

err_mutex_unlock:
    assert(debug_check(coarse_provider));

    if (utils_mutex_unlock(&coarse_provider->lock) != 0) {
        LOG_ERR("unlocking the lock failed");
        if (umf_result == UMF_RESULT_SUCCESS) {
            umf_result = UMF_RESULT_ERROR_UNKNOWN;
        }
    }

    return umf_result;
}

static umf_result_t coarse_memory_provider_allocation_merge(void *provider,
                                                            void *lowPtr,
                                                            void *highPtr,
                                                            size_t totalSize) {
    if (provider == NULL || lowPtr == NULL || highPtr == NULL ||
        ((uintptr_t)highPtr <= (uintptr_t)lowPtr) ||
        ((uintptr_t)highPtr - (uintptr_t)lowPtr >= totalSize)) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_result_t umf_result;

    coarse_memory_provider_t *coarse_provider =
        (struct coarse_memory_provider_t *)provider;

    if (utils_mutex_lock(&coarse_provider->lock) != 0) {
        LOG_ERR("locking the lock failed");
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    assert(debug_check(coarse_provider));

    ravl_node_t *low_node =
        coarse_ravl_find_node(coarse_provider->all_blocks, lowPtr);
    if (low_node == NULL) {
        LOG_ERR("the lowPtr memory block not found");
        umf_result = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err_mutex_unlock;
    }

    block_t *low_block = get_node_block(low_node);
    if (!low_block->used) {
        LOG_ERR("the lowPtr block is not allocated");
        umf_result = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err_mutex_unlock;
    }

    ravl_node_t *high_node =
        coarse_ravl_find_node(coarse_provider->all_blocks, highPtr);
    if (high_node == NULL) {
        LOG_ERR("the highPtr memory block not found");
        umf_result = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err_mutex_unlock;
    }

    block_t *high_block = get_node_block(high_node);
    if (!high_block->used) {
        LOG_ERR("the highPtr block is not allocated");
        umf_result = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err_mutex_unlock;
    }

    if (get_node_next(low_node) != high_node) {
        LOG_ERR("given pointers cannot be merged");
        umf_result = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err_mutex_unlock;
    }

    if (get_node_prev(high_node) != low_node) {
        LOG_ERR("given pointers cannot be merged");
        umf_result = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err_mutex_unlock;
    }

    if (low_block->size + high_block->size != totalSize) {
        LOG_ERR("wrong totalSize");
        umf_result = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err_mutex_unlock;
    }

    if ((uintptr_t)highPtr != ((uintptr_t)lowPtr + low_block->size)) {
        LOG_ERR("given pointers cannot be merged");
        umf_result = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err_mutex_unlock;
    }

    ravl_node_t *merged_node = NULL;

    umf_result = user_block_merge(coarse_provider, low_node, high_node, true,
                                  &merged_node);
    if (umf_result != UMF_RESULT_SUCCESS) {
        LOG_ERR("merging failed");
        goto err_mutex_unlock;
    }

    assert(merged_node == low_node);
    assert(low_block->size == totalSize);

    umf_result = UMF_RESULT_SUCCESS;

err_mutex_unlock:
    assert(debug_check(coarse_provider));

    if (utils_mutex_unlock(&coarse_provider->lock) != 0) {
        LOG_ERR("unlocking the lock failed");
        if (umf_result == UMF_RESULT_SUCCESS) {
            umf_result = UMF_RESULT_ERROR_UNKNOWN;
        }
    }

    return umf_result;
}

umf_memory_provider_ops_t UMF_COARSE_MEMORY_PROVIDER_OPS = {
    .version = UMF_VERSION_CURRENT,
    .initialize = coarse_memory_provider_initialize,
    .finalize = coarse_memory_provider_finalize,
    .alloc = coarse_memory_provider_alloc,
    .get_last_native_error = coarse_memory_provider_get_last_native_error,
    .get_recommended_page_size =
        coarse_memory_provider_get_recommended_page_size,
    .get_min_page_size = coarse_memory_provider_get_min_page_size,
    .get_name = coarse_memory_provider_get_name,
    .ext.free = coarse_memory_provider_free,
    .ext.purge_lazy = coarse_memory_provider_purge_lazy,
    .ext.purge_force = coarse_memory_provider_purge_force,
    .ext.allocation_merge = coarse_memory_provider_allocation_merge,
    .ext.allocation_split = coarse_memory_provider_allocation_split,
    // TODO
    /*
    .ipc.get_ipc_handle_size = coarse_memory_provider_get_ipc_handle_size,
    .ipc.get_ipc_handle = coarse_memory_provider_get_ipc_handle,
    .ipc.put_ipc_handle = coarse_memory_provider_put_ipc_handle,
    .ipc.open_ipc_handle = coarse_memory_provider_open_ipc_handle,
    .ipc.close_ipc_handle = coarse_memory_provider_close_ipc_handle,
    */
};

umf_memory_provider_ops_t *umfCoarseMemoryProviderOps(void) {
    return &UMF_COARSE_MEMORY_PROVIDER_OPS;
}

coarse_memory_provider_stats_t
umfCoarseMemoryProviderGetStats(umf_memory_provider_handle_t provider) {
    coarse_memory_provider_stats_t stats = {0};

    if (provider == NULL) {
        return stats;
    }

    void *priv = umfMemoryProviderGetPriv(provider);

    coarse_memory_provider_t *coarse_provider =
        (struct coarse_memory_provider_t *)priv;

    if (utils_mutex_lock(&coarse_provider->lock) != 0) {
        LOG_ERR("locking the lock failed");
        return stats;
    }

    coarse_memory_provider_get_stats(priv, &stats);

    utils_mutex_unlock(&coarse_provider->lock);

    return stats;
}
