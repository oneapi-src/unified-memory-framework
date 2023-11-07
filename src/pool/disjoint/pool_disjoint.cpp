// Copyright (C) 2023 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <umf/memory_pool_ops.h>
#include <umf/memory_provider.h>

#include "pool/pool_disjoint.h"
#include "pool_disjoint_impl.hpp"

struct disjoint_memory_pool {
    usm::DisjointPool *disjoint_pool;
};

enum umf_result_t
disjoint_pool_initialize(umf_memory_provider_handle_t provider,
                         void *params, void **pool) try {
    struct umf_disjoint_pool_params *pub_params = (struct umf_disjoint_pool_params *)params;
    usm::DisjointPoolConfig config{};
    config.SlabMinSize = pub_params->SlabMinSize;
    config.MaxPoolableSize = pub_params->MaxPoolableSize;
    config.Capacity = pub_params->Capacity;
    config.MinBucketSize = pub_params->MinBucketSize;
    config.CurPoolSize = pub_params->CurPoolSize;
    config.PoolTrace = pub_params->PoolTrace;

    struct disjoint_memory_pool *pool_data = new struct disjoint_memory_pool;
    pool_data->disjoint_pool = new usm::DisjointPool();
    pool_data->disjoint_pool->initialize(provider, config);
    *pool = (void *)pool_data;
    return UMF_RESULT_SUCCESS;
} catch(std::bad_alloc&) {
   return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
} catch (...) {
   return UMF_RESULT_ERROR_UNKNOWN;
}

void disjoint_pool_finalize(void *pool) {
    struct disjoint_memory_pool *pool_data =
        (struct disjoint_memory_pool *)pool;
    delete pool_data->disjoint_pool;
    delete pool_data;
    pool = NULL;
}

void *disjoint_malloc(void *pool, size_t size) {
    struct disjoint_memory_pool *pool_data =
        (struct disjoint_memory_pool *)pool;
    return pool_data->disjoint_pool->malloc(size);
}

void *disjoint_calloc(void *pool, size_t num, size_t size) {
    struct disjoint_memory_pool *pool_data =
        (struct disjoint_memory_pool *)pool;
    return pool_data->disjoint_pool->calloc(num, size);
}

void *disjoint_realloc(void *pool, void *ptr, size_t size) {
    struct disjoint_memory_pool *pool_data =
        (struct disjoint_memory_pool *)pool;
    return pool_data->disjoint_pool->realloc(ptr, size);
}

void *disjoint_aligned_malloc(void *pool, size_t size, size_t alignment) {
    struct disjoint_memory_pool *pool_data =
        (struct disjoint_memory_pool *)pool;
    return pool_data->disjoint_pool->aligned_malloc(size, alignment);
}

enum umf_result_t disjoint_free(void *pool, void *ptr) {
    struct disjoint_memory_pool *pool_data =
        (struct disjoint_memory_pool *)pool;
    pool_data->disjoint_pool->free(ptr);
    return UMF_RESULT_SUCCESS;
}

enum umf_result_t disjoint_get_last_allocation_error(void *pool) {
    struct disjoint_memory_pool *pool_data =
        (struct disjoint_memory_pool *)pool;
    return pool_data->disjoint_pool->get_last_allocation_error();
}

/*
 * Do not use C++ designated initializers,
 * because they are available starting from C++20,
 * when [-Wpedantic] is set and they are treated
 * as an error on Windows.
 */
struct umf_memory_pool_ops_t UMF_DISJOINT_POOL_OPS = {
    /* .version = */ UMF_VERSION_CURRENT,
    /* .initialize = */ disjoint_pool_initialize,
    /* .finalize = */ disjoint_pool_finalize,
    /* .malloc = */ disjoint_malloc,
    /* .calloc = */ disjoint_calloc,
    /* .realloc = */ disjoint_realloc,
    /* .aligned_malloc = */ disjoint_aligned_malloc,
    /* .malloc_usable_size = */ NULL,
    /* .free = */ disjoint_free,
    /* .get_last_allocation_error = */ disjoint_get_last_allocation_error,
};
