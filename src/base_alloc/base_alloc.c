/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <assert.h>

#include "base_alloc.h"
#include "base_alloc_internal.h"
#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_log.h"
#include "utils_sanitizers.h"

// minimum size of a single pool of the base allocator
#define MINIMUM_POOL_SIZE (ba_os_get_page_size())

// minimum number of chunks used to calculate the size of pools
#define MINIMUM_CHUNK_COUNT (128)

// alignment of the base allocator
#define MEMORY_ALIGNMENT (sizeof(uintptr_t))

typedef struct umf_ba_chunk_t umf_ba_chunk_t;
typedef struct umf_ba_next_pool_t umf_ba_next_pool_t;

// memory chunk of size 'chunk_size'
struct umf_ba_chunk_t {
    umf_ba_chunk_t *next;
    char user_data[];
};

// metadata is set and used only in the main (the first) pool
struct umf_ba_main_pool_meta_t {
    size_t pool_size; // size of each pool (argument of each ba_os_alloc() call)
    size_t chunk_size;         // size of all memory chunks in this pool
    utils_mutex_t free_lock;   // lock of free_list
    umf_ba_chunk_t *free_list; // list of free chunks
    size_t n_allocs;           // number of allocated chunks
#ifndef NDEBUG
    size_t n_pools;
    size_t n_chunks;
#endif /* NDEBUG */
};

// the main pool of the base allocator (there is only one such pool)
struct umf_ba_pool_t {
    // address of the beginning of the next pool (a list of allocated pools to be freed in umf_ba_destroy())
    umf_ba_next_pool_t *next_pool;

    // metadata is set and used only in the main (the first) pool
    struct umf_ba_main_pool_meta_t metadata;

    // data area of the main pool (the first one) starts here
    char data[];
};

// the "next" pools of the base allocator (pools allocated later, when we run out of the memory of the main pool)
struct umf_ba_next_pool_t {
    // address of the beginning of the next pool (a list of allocated pools to be freed in umf_ba_destroy())
    umf_ba_next_pool_t *next_pool;

    // data area of all pools except of the main (the first one) starts here
    char data[];
};

#ifndef NDEBUG
static void ba_debug_checks(umf_ba_pool_t *pool) {
    // count pools
    size_t n_pools = 1;
    umf_ba_next_pool_t *next_pool = pool->next_pool;
    while (next_pool) {
        n_pools++;
        next_pool = next_pool->next_pool;
    }
    assert(n_pools == pool->metadata.n_pools);

    // count chunks
    size_t n_free_chunks = 0;
    umf_ba_chunk_t *next_chunk = pool->metadata.free_list;
    while (next_chunk) {
        n_free_chunks++;
        utils_annotate_memory_defined(next_chunk, sizeof(umf_ba_chunk_t));
        umf_ba_chunk_t *tmp = next_chunk;
        next_chunk = next_chunk->next;
        utils_annotate_memory_inaccessible(tmp, sizeof(umf_ba_chunk_t));
    }
    assert(n_free_chunks == pool->metadata.n_chunks - pool->metadata.n_allocs);
}
#endif /* NDEBUG */

// ba_divide_memory_into_chunks - divide given memory into chunks of chunk_size and add them to the free_list
static void ba_divide_memory_into_chunks(umf_ba_pool_t *pool, void *ptr,
                                         size_t size) {
    // mark the memory temporarily accessible to perform the division
    utils_annotate_memory_undefined(ptr, size);

    assert(pool->metadata.free_list == NULL);
    assert(size > pool->metadata.chunk_size);

    char *data_ptr = ptr;
    size_t size_left = size;

    umf_ba_chunk_t *current_chunk = (umf_ba_chunk_t *)data_ptr;
    umf_ba_chunk_t *prev_chunk = current_chunk;

    while (size_left >= pool->metadata.chunk_size) {
        current_chunk = (umf_ba_chunk_t *)data_ptr;
        prev_chunk->next = current_chunk;

        data_ptr += pool->metadata.chunk_size;
        size_left -= pool->metadata.chunk_size;
        prev_chunk = current_chunk;
#ifndef NDEBUG
        pool->metadata.n_chunks++;
#endif /* NDEBUG */
    }

    current_chunk->next = NULL;
    pool->metadata.free_list = ptr; // address of the first chunk

    // mark the memory as unaccessible again
    utils_annotate_memory_inaccessible(ptr, size);
}

static void *ba_os_alloc_annotated(size_t pool_size) {
    void *ptr = ba_os_alloc(pool_size);
    if (ptr) {
        utils_annotate_memory_inaccessible(ptr, pool_size);
    }
    return ptr;
}

umf_ba_pool_t *umf_ba_create(size_t size) {
    size_t chunk_size = ALIGN_UP(size, MEMORY_ALIGNMENT);
    size_t mutex_size = ALIGN_UP(utils_mutex_get_size(), MEMORY_ALIGNMENT);

    size_t metadata_size = sizeof(struct umf_ba_main_pool_meta_t);
    size_t pool_size = sizeof(void *) + metadata_size + mutex_size +
                       (MINIMUM_CHUNK_COUNT * chunk_size);
    if (pool_size < MINIMUM_POOL_SIZE) {
        pool_size = MINIMUM_POOL_SIZE;
    }

    pool_size = ALIGN_UP(pool_size, ba_os_get_page_size());

    umf_ba_pool_t *pool = (umf_ba_pool_t *)ba_os_alloc_annotated(pool_size);
    if (!pool) {
        return NULL;
    }

    // annotate metadata region as accessible
    utils_annotate_memory_undefined(pool, offsetof(umf_ba_pool_t, data));

    pool->metadata.pool_size = pool_size;
    pool->metadata.chunk_size = chunk_size;
    pool->next_pool = NULL; // this is the only pool now
    pool->metadata.n_allocs = 0;
#ifndef NDEBUG
    pool->metadata.n_pools = 1;
    pool->metadata.n_chunks = 0;
#endif /* NDEBUG */

    utils_annotate_memory_defined(pool, offsetof(umf_ba_pool_t, data));

    char *data_ptr = (char *)&pool->data;
    size_t size_left = pool_size - offsetof(umf_ba_pool_t, data);

    utils_align_ptr_up_size_down((void **)&data_ptr, &size_left,
                                 MEMORY_ALIGNMENT);

    // init free_lock
    utils_mutex_t *mutex = utils_mutex_init(&pool->metadata.free_lock);
    if (!mutex) {
        ba_os_free(pool, pool_size);
        return NULL;
    }

    pool->metadata.free_list = NULL;
    ba_divide_memory_into_chunks(pool, data_ptr, size_left);

    return pool;
}

void *umf_ba_alloc(umf_ba_pool_t *pool) {
    utils_mutex_lock(&pool->metadata.free_lock);
    if (pool->metadata.free_list == NULL) {
        umf_ba_next_pool_t *new_pool =
            (umf_ba_next_pool_t *)ba_os_alloc_annotated(
                pool->metadata.pool_size);
        if (!new_pool) {
            utils_mutex_unlock(&pool->metadata.free_lock);
            return NULL;
        }

        // annotate metadata region as accessible
        utils_annotate_memory_undefined(new_pool, sizeof(umf_ba_next_pool_t));

        // add the new pool to the list of pools
        new_pool->next_pool = pool->next_pool;
        pool->next_pool = new_pool;

#ifndef NDEBUG
        pool->metadata.n_pools++;
#endif /* NDEBUG */

        char *data_ptr = (char *)&new_pool->data;
        size_t size_left =
            pool->metadata.pool_size - offsetof(umf_ba_next_pool_t, data);

        utils_align_ptr_up_size_down((void **)&data_ptr, &size_left,
                                     MEMORY_ALIGNMENT);
        ba_divide_memory_into_chunks(pool, data_ptr, size_left);
    }

    umf_ba_chunk_t *chunk = pool->metadata.free_list;

    // mark the memory defined to read the next ptr, after this is done
    // we'll mark the memory as undefined
    utils_annotate_memory_defined(chunk, sizeof(*chunk));

    // check if the free list is not empty
    if (pool->metadata.free_list == NULL) {
        LOG_ERR("base_alloc: Free list should not be empty before new alloc");
        return NULL;
    }

    pool->metadata.free_list = pool->metadata.free_list->next;
    pool->metadata.n_allocs++;
#ifndef NDEBUG
    ba_debug_checks(pool);
#endif /* NDEBUG */

    VALGRIND_DO_MALLOCLIKE_BLOCK(chunk, pool->metadata.chunk_size, 0, 0);
    utils_annotate_memory_undefined(chunk, pool->metadata.chunk_size);

    utils_mutex_unlock(&pool->metadata.free_lock);

    return chunk;
}

#ifndef NDEBUG
// Checks if given pointer belongs to the pool. Should be called
// under the lock
static int pool_contains_pointer(umf_ba_pool_t *pool, void *ptr) {
    char *cptr = (char *)ptr;
    if (cptr >= pool->data &&
        cptr < ((char *)(pool)) + pool->metadata.pool_size) {
        return 1;
    }

    umf_ba_next_pool_t *next_pool = pool->next_pool;
    while (next_pool) {
        if (cptr >= next_pool->data &&
            cptr < ((char *)(next_pool)) + pool->metadata.pool_size) {
            return 1;
        }
        next_pool = next_pool->next_pool;
    }

    return 0;
}
#endif

void umf_ba_free(umf_ba_pool_t *pool, void *ptr) {
    if (ptr == NULL) {
        return;
    }

    umf_ba_chunk_t *chunk = (umf_ba_chunk_t *)ptr;

    utils_mutex_lock(&pool->metadata.free_lock);
    assert(pool_contains_pointer(pool, ptr));
    chunk->next = pool->metadata.free_list;
    pool->metadata.free_list = chunk;
    pool->metadata.n_allocs--;
#ifndef NDEBUG
    ba_debug_checks(pool);
#endif /* NDEBUG */

    VALGRIND_DO_FREELIKE_BLOCK(chunk, 0);
    utils_annotate_memory_inaccessible(chunk, pool->metadata.chunk_size);

    utils_mutex_unlock(&pool->metadata.free_lock);
}

void umf_ba_destroy(umf_ba_pool_t *pool) {
    // Do not destroy if we are running in the proxy library,
    // because it may need those resources till
    // the very end of exiting the application.
    if (pool->metadata.n_allocs && utils_is_running_in_proxy_lib()) {
        return;
    }

#ifndef NDEBUG
    ba_debug_checks(pool);
    if (pool->metadata.n_allocs) {
        LOG_ERR("pool->metadata.n_allocs = %zu", pool->metadata.n_allocs);
    }
#endif /* NDEBUG */

    size_t size = pool->metadata.pool_size;
    umf_ba_next_pool_t *current_pool;
    umf_ba_next_pool_t *next_pool = pool->next_pool;
    while (next_pool) {
        current_pool = next_pool;
        next_pool = next_pool->next_pool;
        ba_os_free(current_pool, size);
    }

    utils_mutex_destroy_not_free(&pool->metadata.free_lock);
    ba_os_free(pool, size);
}
