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

// metadata of the linear base allocator
typedef struct {
    size_t pool_size;
    os_mutex_t lock;
    char *data_ptr;
    size_t size_left;
} umf_ba_main_linear_pool_meta_t;

// pool of the linear base allocator
struct umf_ba_linear_pool {
    umf_ba_main_linear_pool_meta_t metadata;
    char data[]; // data area starts here
};

umf_ba_linear_pool_t *umf_ba_linear_create(size_t pool_size) {
    size_t mutex_size = align_size(util_mutex_get_size(), MEMORY_ALIGNMENT);
    size_t metadata_size = sizeof(umf_ba_main_linear_pool_meta_t);
    pool_size = pool_size + metadata_size + mutex_size;
    if (pool_size < MINIMUM_LINEAR_POOL_SIZE) {
        pool_size = MINIMUM_LINEAR_POOL_SIZE;
    }

    pool_size = align_size(pool_size, ba_os_get_page_size());

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

    // init lock
    os_mutex_t *lock = util_mutex_init(&pool->metadata.lock);
    if (!lock) {
        ba_os_free(pool, pool_size);
        return NULL;
    }

    return pool;
}

void *umf_ba_linear_alloc(umf_ba_linear_pool_t *pool, size_t size) {
    size_t aligned_size = align_size(size, MEMORY_ALIGNMENT);

    util_mutex_lock(&pool->metadata.lock);
    if (pool->metadata.size_left < aligned_size) {
        util_mutex_unlock(&pool->metadata.lock);
        return NULL; // out of memory
    }

    void *ptr = pool->metadata.data_ptr;
    pool->metadata.data_ptr += aligned_size;
    pool->metadata.size_left -= aligned_size;
    util_mutex_unlock(&pool->metadata.lock);

    return ptr;
}

void umf_ba_linear_destroy(umf_ba_linear_pool_t *pool) {
    util_mutex_destroy_not_free(&pool->metadata.lock);
    ba_os_free(pool, pool->metadata.pool_size);
}
