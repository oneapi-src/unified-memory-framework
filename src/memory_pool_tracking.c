/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "memory_pool_internal.h"
#include "memory_provider_internal.h"
#include "provider_tracking.h"

#include <umf/memory_pool.h>

#include <assert.h>
#include <stdlib.h>

umf_result_t umfPoolCreate(const umf_memory_pool_ops_t *ops,
                           umf_memory_provider_handle_t provider, void *params,
                           umf_memory_pool_handle_t *hPool) {
    if (!provider) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_result_t ret = UMF_RESULT_SUCCESS;
    umf_memory_pool_handle_t pool = malloc(sizeof(umf_memory_pool_t));
    if (!pool) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    assert(ops->version == UMF_VERSION_CURRENT);

    // wrap provider with memory tracking provider
    ret = umfTrackingMemoryProviderCreate(provider, pool, &pool->provider);
    if (ret != UMF_RESULT_SUCCESS) {
        goto err_provider_create;
    }
    pool->own_provider = false;

    pool->ops = *ops;
    ret = ops->initialize(pool->provider, params, &pool->pool_priv);
    if (ret != UMF_RESULT_SUCCESS) {
        goto err_pool_init;
    }

    *hPool = pool;
    return UMF_RESULT_SUCCESS;

err_pool_init:
    umfMemoryProviderDestroy(pool->provider);
err_provider_create:
    free(pool);

    return ret;
}

void umfPoolDestroy(umf_memory_pool_handle_t hPool) {
    hPool->ops.finalize(hPool->pool_priv);
    if (hPool->own_provider) {
        // Destroy associated memory provider.
        umf_memory_provider_handle_t hProvider = NULL;
        umfPoolGetMemoryProvider(hPool, &hProvider);
        umfMemoryProviderDestroy(hProvider);
    }
    // Destroy tracking provider.
    umfMemoryProviderDestroy(hPool->provider);
    free(hPool);
}

umf_result_t umfFree(void *ptr) {
    umf_memory_pool_handle_t hPool = umfPoolByPtr(ptr);
    if (hPool) {
        return umfPoolFree(hPool, ptr);
    }
    return UMF_RESULT_SUCCESS;
}

umf_memory_pool_handle_t umfPoolByPtr(const void *ptr) {
    return umfMemoryTrackerGetPool(umfMemoryTrackerGet(), ptr);
}

umf_result_t umfPoolGetMemoryProvider(umf_memory_pool_handle_t hPool,
                                      umf_memory_provider_handle_t *hProvider) {
    if (!hProvider) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umfTrackingMemoryProviderGetUpstreamProvider(
        umfMemoryProviderGetPriv(hPool->provider), hProvider);

    return UMF_RESULT_SUCCESS;
}
