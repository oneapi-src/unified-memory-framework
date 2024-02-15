/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <assert.h>
#include <stdint.h>

#include "base_alloc_internal.h"
#include "base_alloc_linear.h"
#include "utils_common.h"
#include "utils_concurrency.h"

// minimum size of a single pool of the linear base allocator
#define MINIMUM_LINEAR_POOL_SIZE (ba_os_get_page_size())

// alignment of the linear base allocator
#define MEMORY_ALIGNMENT (sizeof(uintptr_t))

typedef struct umf_ba_next_linear_pool_t umf_ba_next_linear_pool_t;

// metadata is set and used only in the main (the first) pool
typedef struct umf_ba_main_linear_pool_meta_t {
    size_t pool_size; // size of this pool (argument of ba_os_alloc() call)
    os_mutex_t lock;
    char *data_ptr;
    size_t size_left;
#ifndef NDEBUG
    size_t n_pools;
#endif /* NDEBUG */
} umf_ba_main_linear_pool_meta_t;

// the main pool of the linear base allocator (there is only one such pool)
struct umf_ba_linear_pool {
    // address of the beginning of the next pool (a list of allocated pools
    // to be freed in umf_ba_linear_destroy())
    umf_ba_next_linear_pool_t *next_pool;

    // metadata is set and used only in the main (the first) pool
    umf_ba_main_linear_pool_meta_t metadata;

    // data area of the main pool (the first one) starts here
    char data[];
};

// the "next" pools of the linear base allocator (pools allocated later,
// when we run out of the memory of the main pool)
struct umf_ba_next_linear_pool_t {
    // address of the beginning of the next pool (a list of allocated pools
    // to be freed in umf_ba_linear_destroy())
    umf_ba_next_linear_pool_t *next_pool;

    size_t pool_size; // size of this pool (argument of ba_os_alloc() call)

    // data area of all pools except of the main (the first one) starts here
    char data[];
};

#ifndef NDEBUG
static void ba_debug_checks(umf_ba_linear_pool_t *pool) {
    // count pools
    size_t n_pools = 1;
    umf_ba_next_linear_pool_t *next_pool = pool->next_pool;
    while (next_pool) {
        n_pools++;
        next_pool = next_pool->next_pool;
    }
    assert(n_pools == pool->metadata.n_pools);
}
#endif /* NDEBUG */

umf_ba_linear_pool_t *umf_ba_linear_create(size_t pool_size) {
    pool_size += sizeof(umf_ba_next_linear_pool_t *) +
                 sizeof(umf_ba_main_linear_pool_meta_t);
    if (pool_size < MINIMUM_LINEAR_POOL_SIZE) {
        pool_size = MINIMUM_LINEAR_POOL_SIZE;
    }

    pool_size = ALIGN_UP(pool_size, ba_os_get_page_size());

    umf_ba_linear_pool_t *pool = (umf_ba_linear_pool_t *)ba_os_alloc(pool_size);
    if (!pool) {
        return NULL;
    }

    void *data_ptr = &pool->data;
    size_t size_left = pool_size - offsetof(umf_ba_linear_pool_t, data);

    align_ptr_size(&data_ptr, &size_left, MEMORY_ALIGNMENT);

    pool->metadata.pool_size = pool_size;
    pool->metadata.data_ptr = data_ptr;
    pool->metadata.size_left = size_left;
    pool->next_pool = NULL; // this is the only pool now
#ifndef NDEBUG
    pool->metadata.n_pools = 1;
#endif /* NDEBUG */

    // init lock
    os_mutex_t *lock = util_mutex_init(&pool->metadata.lock);
    if (!lock) {
        ba_os_free(pool, pool_size);
        return NULL;
    }

    return pool;
}

void *umf_ba_linear_alloc(umf_ba_linear_pool_t *pool, size_t size) {
    size_t aligned_size = ALIGN_UP(size, MEMORY_ALIGNMENT);
    util_mutex_lock(&pool->metadata.lock);
    if (pool->metadata.size_left < aligned_size) {
        size_t pool_size = MINIMUM_LINEAR_POOL_SIZE;
        size_t usable_size =
            pool_size - offsetof(umf_ba_next_linear_pool_t, data);
        if (usable_size < aligned_size) {
            pool_size += aligned_size - usable_size;
            pool_size = ALIGN_UP(pool_size, ba_os_get_page_size());
        }

        assert(pool_size - offsetof(umf_ba_next_linear_pool_t, data) >=
               aligned_size);

        umf_ba_next_linear_pool_t *new_pool =
            (umf_ba_next_linear_pool_t *)ba_os_alloc(pool_size);
        if (!new_pool) {
            util_mutex_unlock(&pool->metadata.lock);
            return NULL;
        }

        new_pool->pool_size = pool_size;

        void *data_ptr = &new_pool->data;
        size_t size_left =
            new_pool->pool_size - offsetof(umf_ba_next_linear_pool_t, data);
        align_ptr_size(&data_ptr, &size_left, MEMORY_ALIGNMENT);

        pool->metadata.data_ptr = data_ptr;
        pool->metadata.size_left = size_left;

        // add the new pool to the list of pools
        new_pool->next_pool = pool->next_pool;
        pool->next_pool = new_pool;
#ifndef NDEBUG
        pool->metadata.n_pools++;
#endif /* NDEBUG */
    }

    assert(pool->metadata.size_left >= aligned_size);
    void *ptr = pool->metadata.data_ptr;
    pool->metadata.data_ptr += aligned_size;
    pool->metadata.size_left -= aligned_size;
#ifndef NDEBUG
    ba_debug_checks(pool);
#endif /* NDEBUG */
    util_mutex_unlock(&pool->metadata.lock);

    return ptr;
}

void umf_ba_linear_destroy(umf_ba_linear_pool_t *pool) {
#ifndef NDEBUG
    ba_debug_checks(pool);
#endif /* NDEBUG */
    umf_ba_next_linear_pool_t *current_pool;
    umf_ba_next_linear_pool_t *next_pool = pool->next_pool;
    while (next_pool) {
        current_pool = next_pool;
        next_pool = next_pool->next_pool;
        ba_os_free(current_pool, current_pool->pool_size);
    }

    util_mutex_destroy_not_free(&pool->metadata.lock);
    ba_os_free(pool, pool->metadata.pool_size);
}

// umf_ba_linear_pool_contains_pointer() returns:
// - 0 if ptr does not belong to the pool or
// - size (> 0) of the memory region from ptr
//   to the end of the pool if ptr belongs to the pool
size_t umf_ba_linear_pool_contains_pointer(umf_ba_linear_pool_t *pool,
                                           void *ptr) {
    util_mutex_lock(&pool->metadata.lock);
    char *cptr = (char *)ptr;
    if (cptr >= pool->data &&
        cptr < ((char *)(pool)) + pool->metadata.pool_size) {
        size_t size = ((char *)(pool)) + pool->metadata.pool_size - cptr;
        util_mutex_unlock(&pool->metadata.lock);
        return size;
    }

    umf_ba_next_linear_pool_t *next_pool = pool->next_pool;
    while (next_pool) {
        if (cptr >= next_pool->data &&
            cptr < ((char *)(next_pool)) + next_pool->pool_size) {
            size_t size = ((char *)(next_pool)) + next_pool->pool_size - cptr;
            util_mutex_unlock(&pool->metadata.lock);
            return size;
        }
        next_pool = next_pool->next_pool;
    }

    util_mutex_unlock(&pool->metadata.lock);
    return 0;
}
