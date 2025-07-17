/*
 *
 * Copyright (C) 2024-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <umf/memory_pool_ops.h>
#include <umf/pools/pool_proxy.h>

#include <assert.h>

#include "base_alloc_global.h"
#include "provider/provider_tracking.h"
#include "utils_common.h"

static __TLS umf_result_t TLS_last_allocation_error;

struct proxy_memory_pool {
    umf_memory_provider_handle_t hProvider;
};

static umf_result_t
proxy_pool_initialize(umf_memory_provider_handle_t hProvider,
                      const void *params, void **ppPool) {
    (void)params; // unused

    struct proxy_memory_pool *pool =
        umf_ba_global_alloc(sizeof(struct proxy_memory_pool));
    if (!pool) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    pool->hProvider = hProvider;
    *ppPool = (void *)pool;

    return UMF_RESULT_SUCCESS;
}

static umf_result_t proxy_pool_finalize(void *pool) {
    umf_ba_global_free(pool);
    return UMF_RESULT_SUCCESS;
}

static void *proxy_aligned_malloc(void *pool, size_t size, size_t alignment) {
    assert(pool);

    void *ptr;
    struct proxy_memory_pool *hPool = (struct proxy_memory_pool *)pool;

    umf_result_t ret =
        umfMemoryProviderAlloc(hPool->hProvider, size, alignment, &ptr);
    if (ret != UMF_RESULT_SUCCESS) {
        TLS_last_allocation_error = ret;
        return NULL;
    }

    TLS_last_allocation_error = UMF_RESULT_SUCCESS;
    return ptr;
}

static void *proxy_malloc(void *pool, size_t size) {
    assert(pool);

    return proxy_aligned_malloc(pool, size, 0);
}

static void *proxy_calloc(void *pool, size_t num, size_t size) {
    assert(pool);

    (void)pool;
    (void)num;
    (void)size;

    // Currently we cannot implement calloc in a way that would
    // work for memory that is inaccessible on the host
    TLS_last_allocation_error = UMF_RESULT_ERROR_NOT_SUPPORTED;
    return NULL;
}

static void *proxy_realloc(void *pool, void *ptr, size_t size) {
    assert(pool);

    (void)pool;
    (void)ptr;
    (void)size;

    // Currently we cannot implement realloc in a way that would
    // work for memory that is inaccessible on the host
    TLS_last_allocation_error = UMF_RESULT_ERROR_NOT_SUPPORTED;
    return NULL;
}

static umf_result_t proxy_free(void *pool, void *ptr) {
    assert(pool);
    size_t size = 0;

    struct proxy_memory_pool *hPool = (struct proxy_memory_pool *)pool;

    if (ptr) {
        umf_memory_properties_handle_t props = NULL;
        umf_result_t umf_result = umfGetMemoryPropertiesHandle(ptr, &props);

        if (umf_result != UMF_RESULT_SUCCESS) {
            TLS_last_allocation_error = umf_result;
            LOG_ERR("failed to get allocation info from the memory tracker");
            return umf_result;
        }

        if (props == NULL) {
            TLS_last_allocation_error = UMF_RESULT_ERROR_UNKNOWN;
            LOG_ERR("failed to get allocation info from the memory tracker");
            return UMF_RESULT_ERROR_UNKNOWN;
        }

        size = props->base_size;
    }

    return umfMemoryProviderFree(hPool->hProvider, ptr, size);
}

static umf_result_t proxy_malloc_usable_size(void *pool, const void *ptr,
                                             size_t *size) {
    assert(pool);

    (void)pool;
    (void)ptr;
    if (!size) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    TLS_last_allocation_error = UMF_RESULT_ERROR_NOT_SUPPORTED;
    *size = 0;
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

static umf_result_t proxy_get_last_allocation_error(void *pool) {
    (void)pool; // not used
    return TLS_last_allocation_error;
}

static umf_result_t proxy_get_name(void *pool, const char **name) {
    (void)pool;
    *name = "proxy";
    return UMF_RESULT_SUCCESS;
}

static umf_memory_pool_ops_t UMF_PROXY_POOL_OPS = {
    .version = UMF_POOL_OPS_VERSION_CURRENT,
    .initialize = proxy_pool_initialize,
    .finalize = proxy_pool_finalize,
    .malloc = proxy_malloc,
    .calloc = proxy_calloc,
    .realloc = proxy_realloc,
    .aligned_malloc = proxy_aligned_malloc,
    .malloc_usable_size = proxy_malloc_usable_size,
    .free = proxy_free,
    .get_last_allocation_error = proxy_get_last_allocation_error,
    .get_name = proxy_get_name,
    .ext_trim_memory = NULL, // not supported
};

const umf_memory_pool_ops_t *umfProxyPoolOps(void) {
    return &UMF_PROXY_POOL_OPS;
}
