/*
 *
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <assert.h>
#include <stdlib.h>

#include <umf/memory_pool.h>

#include "base_alloc_global.h"
#include "memory_pool_internal.h"
#include "memory_provider_internal.h"

umf_result_t umfPoolCreateInternal(const umf_memory_pool_ops_t *ops,
                                   umf_memory_provider_handle_t provider,
                                   void *params,
                                   umf_memory_pool_handle_t *hPool) {
    if (!ops || !provider || !hPool) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_result_t ret = UMF_RESULT_SUCCESS;
    umf_ba_pool_t *base_allocator = umf_ba_get_pool(sizeof(umf_memory_pool_t));
    if (!base_allocator) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    umf_memory_pool_handle_t pool = umf_ba_alloc(base_allocator);
    if (!pool) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    assert(ops->version == UMF_VERSION_CURRENT);

    pool->base_allocator = base_allocator;
    pool->provider = provider;
    pool->own_provider = false;

    pool->ops = *ops;
    ret = ops->initialize(pool->provider, params, &pool->pool_priv);
    if (ret != UMF_RESULT_SUCCESS) {
        umf_ba_free(base_allocator, pool);
        return ret;
    }

    *hPool = pool;
    return UMF_RESULT_SUCCESS;
}

void umfPoolDestroy(umf_memory_pool_handle_t hPool) {
    hPool->ops.finalize(hPool->pool_priv);
    if (hPool->own_provider) {
        // Destroy associated memory provider.
        umf_memory_provider_handle_t hProvider = NULL;
        umfPoolGetMemoryProvider(hPool, &hProvider);
        umfMemoryProviderDestroy(hProvider);
    }
    // TODO: this free keeps memory in base allocator, so it can lead to OOM in some scenarios (it should be optimized)
    umf_ba_free(hPool->base_allocator, hPool);
}

umf_result_t umfFree(void *ptr) {
    (void)ptr;
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

umf_memory_pool_handle_t umfPoolByPtr(const void *ptr) {
    (void)ptr;
    return NULL;
}

umf_result_t umfPoolGetMemoryProvider(umf_memory_pool_handle_t hPool,
                                      umf_memory_provider_handle_t *hProvider) {
    if (!hProvider) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *hProvider = hPool->provider;

    return UMF_RESULT_SUCCESS;
}
