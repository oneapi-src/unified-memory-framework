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

    pool->provider = provider;
    pool->own_provider = false;

    pool->ops = *ops;
    ret = ops->initialize(pool->provider, params, &pool->pool_priv);
    if (ret != UMF_RESULT_SUCCESS) {
        free(pool);
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
    free(hPool);
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
