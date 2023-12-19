/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "memory_pool_internal.h"

#include <umf/memory_pool.h>
#include <umf/memory_pool_ops.h>

#include <assert.h>
#include <stdlib.h>

umf_result_t umfPoolCreateEx(const umf_memory_pool_ops_t *pool_ops,
                             void *pool_params,
                             const umf_memory_provider_ops_t *provider_ops,
                             void *provider_params,
                             umf_memory_pool_handle_t *hPool) {
    if (!pool_ops || !provider_ops || !hPool) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_memory_provider_handle_t provider = NULL;
    umf_result_t ret =
        umfMemoryProviderCreate(provider_ops, provider_params, &provider);
    if (ret != UMF_RESULT_SUCCESS) {
        return ret;
    }
    assert(provider != NULL);

    umf_memory_pool_handle_t pool = NULL;
    ret = umfPoolCreate(pool_ops, provider, pool_params, &pool);
    if (ret != UMF_RESULT_SUCCESS) {
        umfMemoryProviderDestroy(provider);
        return ret;
    }
    assert(pool != NULL);

    pool->own_provider = true;
    *hPool = pool;

    return UMF_RESULT_SUCCESS;
}

void *umfPoolMalloc(umf_memory_pool_handle_t hPool, size_t size) {
    return hPool->ops.malloc(hPool->pool_priv, size);
}

void *umfPoolAlignedMalloc(umf_memory_pool_handle_t hPool, size_t size,
                           size_t alignment) {
    return hPool->ops.aligned_malloc(hPool->pool_priv, size, alignment);
}

void *umfPoolCalloc(umf_memory_pool_handle_t hPool, size_t num, size_t size) {
    return hPool->ops.calloc(hPool->pool_priv, num, size);
}

void *umfPoolRealloc(umf_memory_pool_handle_t hPool, void *ptr, size_t size) {
    return hPool->ops.realloc(hPool->pool_priv, ptr, size);
}

size_t umfPoolMallocUsableSize(umf_memory_pool_handle_t hPool, void *ptr) {
    return hPool->ops.malloc_usable_size(hPool->pool_priv, ptr);
}

umf_result_t umfPoolFree(umf_memory_pool_handle_t hPool, void *ptr) {
    return hPool->ops.free(hPool->pool_priv, ptr);
}

umf_result_t umfPoolGetLastAllocationError(umf_memory_pool_handle_t hPool) {
    return hPool->ops.get_last_allocation_error(hPool->pool_priv);
}
