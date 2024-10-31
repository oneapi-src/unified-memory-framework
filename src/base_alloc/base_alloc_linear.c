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
#include "utils_log.h"

#ifndef NDEBUG
#define _DEBUG_EXECUTE(expression) DO_WHILE_EXPRS(expression)
#else
#define _DEBUG_EXECUTE(expression) DO_WHILE_EMPTY
#endif /* NDEBUG */

// minimum size of a single pool of the linear base allocator
#define MINIMUM_LINEAR_POOL_SIZE (ba_os_get_page_size())

// alignment of the linear base allocator
#define MEMORY_ALIGNMENT (sizeof(uintptr_t))

typedef struct umf_ba_next_linear_pool_t umf_ba_next_linear_pool_t;

// metadata is set and used only in the main (the first) pool
typedef struct umf_ba_main_linear_pool_meta_t {
    size_t pool_size; // size of this pool (argument of ba_os_alloc() call)
    utils_mutex_t lock;
    char *data_ptr;
    size_t size_left;
    size_t pool_n_allocs; // number of allocations in this pool
#ifndef NDEBUG
    size_t n_pools;
    size_t global_n_allocs; // global number of allocations in all pools
#endif                      /* NDEBUG */
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

    size_t pool_size;     // size of this pool (argument of ba_os_alloc() call)
    size_t pool_n_allocs; // number of allocations in this pool

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

    utils_align_ptr_up_size_down(&data_ptr, &size_left, MEMORY_ALIGNMENT);

    pool->metadata.pool_size = pool_size;
    pool->metadata.data_ptr = data_ptr;
    pool->metadata.size_left = size_left;
    pool->next_pool = NULL; // this is the only pool now
    pool->metadata.pool_n_allocs = 0;
    _DEBUG_EXECUTE(pool->metadata.n_pools = 1);
    _DEBUG_EXECUTE(pool->metadata.global_n_allocs = 0);

    // init lock
    utils_mutex_t *lock = utils_mutex_init(&pool->metadata.lock);
    if (!lock) {
        ba_os_free(pool, pool_size);
        return NULL;
    }

    return pool;
}

void *umf_ba_linear_alloc(umf_ba_linear_pool_t *pool, size_t size) {
    if (size == 0) {
        return NULL;
    }
    size_t aligned_size = ALIGN_UP(size, MEMORY_ALIGNMENT);
    utils_mutex_lock(&pool->metadata.lock);
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
            utils_mutex_unlock(&pool->metadata.lock);
            return NULL;
        }

        new_pool->pool_size = pool_size;
        new_pool->pool_n_allocs = 0;

        void *data_ptr = &new_pool->data;
        size_t size_left =
            new_pool->pool_size - offsetof(umf_ba_next_linear_pool_t, data);
        utils_align_ptr_up_size_down(&data_ptr, &size_left, MEMORY_ALIGNMENT);

        pool->metadata.data_ptr = data_ptr;
        pool->metadata.size_left = size_left;

        // add the new pool to the list of pools
        new_pool->next_pool = pool->next_pool;
        pool->next_pool = new_pool;
        _DEBUG_EXECUTE(pool->metadata.n_pools++);
    }

    assert(pool->metadata.size_left >= aligned_size);
    void *ptr = pool->metadata.data_ptr;
    pool->metadata.data_ptr += aligned_size;
    pool->metadata.size_left -= aligned_size;
    if (pool->next_pool) {
        pool->next_pool->pool_n_allocs++;
    } else {
        pool->metadata.pool_n_allocs++;
    }
    _DEBUG_EXECUTE(pool->metadata.global_n_allocs++);
    _DEBUG_EXECUTE(ba_debug_checks(pool));
    utils_mutex_unlock(&pool->metadata.lock);

    return ptr;
}

// check if ptr belongs to pool
static inline int pool_contains_ptr(void *pool, size_t pool_size,
                                    void *data_begin, void *ptr) {
    return ((char *)ptr >= (char *)data_begin &&
            (char *)ptr < ((char *)(pool)) + pool_size);
}

// umf_ba_linear_free() really frees memory only if all allocations from an inactive pool were freed
// It returns:
// 0  - ptr belonged to the pool and was freed
// -1 - ptr doesn't belong to the pool and wasn't freed
int umf_ba_linear_free(umf_ba_linear_pool_t *pool, void *ptr) {
    utils_mutex_lock(&pool->metadata.lock);
    _DEBUG_EXECUTE(ba_debug_checks(pool));
    if (pool_contains_ptr(pool, pool->metadata.pool_size, pool->data, ptr)) {
        pool->metadata.pool_n_allocs--;
        _DEBUG_EXECUTE(pool->metadata.global_n_allocs--);
        size_t page_size = ba_os_get_page_size();
        if ((pool->metadata.pool_n_allocs == 0) && pool->next_pool &&
            (pool->metadata.pool_size > page_size)) {
            // we can free the first (main) pool except of the first page containing the metadata
            void *pool_ptr = (char *)pool + page_size;
            size_t size = pool->metadata.pool_size - page_size;
            ba_os_free(pool_ptr, size);
            // update pool_size
            pool->metadata.pool_size = page_size;
        }
        _DEBUG_EXECUTE(ba_debug_checks(pool));
        utils_mutex_unlock(&pool->metadata.lock);
        return 0;
    }

    umf_ba_next_linear_pool_t *next_pool = pool->next_pool;
    umf_ba_next_linear_pool_t *prev_pool = NULL;
    while (next_pool) {
        if (pool_contains_ptr(next_pool, next_pool->pool_size, next_pool->data,
                              ptr)) {
            _DEBUG_EXECUTE(pool->metadata.global_n_allocs--);
            next_pool->pool_n_allocs--;
            // pool->next_pool is the active pool - we cannot free it
            if ((next_pool->pool_n_allocs == 0) &&
                next_pool != pool->next_pool) {
                assert(prev_pool); // it cannot be the active pool
                assert(prev_pool->next_pool == next_pool);
                prev_pool->next_pool = next_pool->next_pool;
                _DEBUG_EXECUTE(pool->metadata.n_pools--);
                void *next_pool_ptr = next_pool;
                size_t size = next_pool->pool_size;
                ba_os_free(next_pool_ptr, size);
            }
            _DEBUG_EXECUTE(ba_debug_checks(pool));
            utils_mutex_unlock(&pool->metadata.lock);
            return 0;
        }
        prev_pool = next_pool;
        next_pool = next_pool->next_pool;
    }

    utils_mutex_unlock(&pool->metadata.lock);
    // ptr doesn't belong to the pool and wasn't freed
    return -1;
}

void umf_ba_linear_destroy(umf_ba_linear_pool_t *pool) {
    // Do not destroy if we are running in the proxy library,
    // because it may need those resources till
    // the very end of exiting the application.
    if (utils_is_running_in_proxy_lib()) {
        return;
    }

#ifndef NDEBUG
    _DEBUG_EXECUTE(ba_debug_checks(pool));
    if (pool->metadata.global_n_allocs) {
        LOG_ERR("global_n_allocs = %zu", pool->metadata.global_n_allocs);
    }
#endif /* NDEBUG */

    umf_ba_next_linear_pool_t *current_pool;
    umf_ba_next_linear_pool_t *next_pool = pool->next_pool;
    while (next_pool) {
        current_pool = next_pool;
        next_pool = next_pool->next_pool;
        ba_os_free(current_pool, current_pool->pool_size);
    }

    utils_mutex_destroy_not_free(&pool->metadata.lock);
    ba_os_free(pool, pool->metadata.pool_size);
}

// umf_ba_linear_pool_contains_pointer() returns:
// - 0 if ptr does not belong to the pool or
// - size (> 0) of the memory region from ptr
//   to the end of the pool if ptr belongs to the pool
size_t umf_ba_linear_pool_contains_pointer(umf_ba_linear_pool_t *pool,
                                           void *ptr) {
    utils_mutex_lock(&pool->metadata.lock);
    char *cptr = (char *)ptr;
    if (cptr >= pool->data &&
        cptr < ((char *)(pool)) + pool->metadata.pool_size) {
        size_t size = ((char *)(pool)) + pool->metadata.pool_size - cptr;
        utils_mutex_unlock(&pool->metadata.lock);
        return size;
    }

    umf_ba_next_linear_pool_t *next_pool = pool->next_pool;
    while (next_pool) {
        if (cptr >= next_pool->data &&
            cptr < ((char *)(next_pool)) + next_pool->pool_size) {
            size_t size = ((char *)(next_pool)) + next_pool->pool_size - cptr;
            utils_mutex_unlock(&pool->metadata.lock);
            return size;
        }
        next_pool = next_pool->next_pool;
    }

    utils_mutex_unlock(&pool->metadata.lock);
    return 0;
}
