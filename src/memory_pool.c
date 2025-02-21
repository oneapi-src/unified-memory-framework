/*
 *
 * Copyright (C) 2023-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "libumf.h"
#include "memory_pool_internal.h"
#include "utils_assert.h"

#include <umf/memory_pool.h>
#include <umf/memory_pool_ops.h>

#include <assert.h>
#include <stdlib.h>

#include "base_alloc_global.h"
#include "memory_pool_internal.h"
#include "memory_provider_internal.h"
#include "provider_tracking.h"

static umf_result_t umfPoolCreateInternal(const umf_memory_pool_ops_t *ops,
                                          umf_memory_provider_handle_t provider,
                                          void *params,
                                          umf_pool_create_flags_t flags,
                                          umf_memory_pool_handle_t *hPool) {
    if (!ops || !provider || !hPool) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_result_t ret = UMF_RESULT_SUCCESS;
    umf_memory_pool_handle_t pool =
        umf_ba_global_alloc(sizeof(umf_memory_pool_t));
    if (!pool) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    if (ops->version != UMF_POOL_OPS_VERSION_CURRENT) {
        LOG_WARN("Memory Pool ops version \"%d\" is different than the current "
                 "version \"%d\"",
                 ops->version, UMF_POOL_OPS_VERSION_CURRENT);
    }

    if (!(flags & UMF_POOL_CREATE_FLAG_DISABLE_TRACKING)) {
        // Wrap provider with memory tracking provider.
        ret = umfTrackingMemoryProviderCreate(provider, pool, &pool->provider);
        if (ret != UMF_RESULT_SUCCESS) {
            goto err_provider_create;
        }
    } else {
        pool->provider = provider;
    }

    pool->flags = flags;
    pool->ops = *ops;
    pool->tag = NULL;

    if (NULL == utils_mutex_init(&pool->lock)) {
        LOG_ERR("Failed to initialize mutex for pool");
        ret = UMF_RESULT_ERROR_UNKNOWN;
        goto err_lock_init;
    }

    ret = ops->initialize(pool->provider, params, &pool->pool_priv);
    if (ret != UMF_RESULT_SUCCESS) {
        goto err_pool_init;
    }

    *hPool = pool;
    LOG_INFO("Memory pool created: %p", (void *)pool);
    return UMF_RESULT_SUCCESS;

err_pool_init:
    utils_mutex_destroy_not_free(&pool->lock);
err_lock_init:
    if (!(flags & UMF_POOL_CREATE_FLAG_DISABLE_TRACKING)) {
        umfMemoryProviderDestroy(pool->provider);
    }
err_provider_create:
    umf_ba_global_free(pool);
    return ret;
}

void umfPoolDestroy(umf_memory_pool_handle_t hPool) {
    hPool->ops.finalize(hPool->pool_priv);

    umf_memory_provider_handle_t hUpstreamProvider = NULL;
    umfPoolGetMemoryProvider(hPool, &hUpstreamProvider);

    if (!(hPool->flags & UMF_POOL_CREATE_FLAG_DISABLE_TRACKING)) {
        // Destroy tracking provider.
        umfMemoryProviderDestroy(hPool->provider);
    }

    if (hPool->flags & UMF_POOL_CREATE_FLAG_OWN_PROVIDER) {
        // Destroy associated memory provider.
        umfMemoryProviderDestroy(hUpstreamProvider);
    }

    utils_mutex_destroy_not_free(&hPool->lock);

    LOG_INFO("Memory pool destroyed: %p", (void *)hPool);

    // TODO: this free keeps memory in base allocator, so it can lead to OOM in some scenarios (it should be optimized)
    umf_ba_global_free(hPool);
}

umf_result_t umfFree(void *ptr) {
    umf_memory_pool_handle_t hPool = umfPoolByPtr(ptr);
    if (hPool) {
        return umfPoolFree(hPool, ptr);
    }
    return UMF_RESULT_SUCCESS;
}

umf_memory_pool_handle_t umfPoolByPtr(const void *ptr) {
    return umfMemoryTrackerGetPool(ptr);
}

umf_result_t umfPoolGetMemoryProvider(umf_memory_pool_handle_t hPool,
                                      umf_memory_provider_handle_t *hProvider) {
    if (!hProvider) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (hPool->flags & UMF_POOL_CREATE_FLAG_DISABLE_TRACKING) {
        *hProvider = hPool->provider;
    } else {
        umfTrackingMemoryProviderGetUpstreamProvider(
            umfMemoryProviderGetPriv(hPool->provider), hProvider);
    }

    return UMF_RESULT_SUCCESS;
}

umf_result_t
umfPoolGetTrackingProvider(umf_memory_pool_handle_t hPool,
                           umf_memory_provider_handle_t *hProvider) {
    if (!hPool || !hProvider) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (hPool->flags & UMF_POOL_CREATE_FLAG_DISABLE_TRACKING) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *hProvider = umfMemoryProviderGetPriv(hPool->provider);

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfPoolCreate(const umf_memory_pool_ops_t *ops,
                           umf_memory_provider_handle_t provider, void *params,
                           umf_pool_create_flags_t flags,
                           umf_memory_pool_handle_t *hPool) {
    libumfInit();

    umf_result_t ret =
        umfPoolCreateInternal(ops, provider, params, flags, hPool);
    if (ret != UMF_RESULT_SUCCESS) {
        return ret;
    }
    assert(*hPool != NULL);

    return UMF_RESULT_SUCCESS;
}

void *umfPoolMalloc(umf_memory_pool_handle_t hPool, size_t size) {
    UMF_CHECK((hPool != NULL), NULL);
    return hPool->ops.malloc(hPool->pool_priv, size);
}

void *umfPoolAlignedMalloc(umf_memory_pool_handle_t hPool, size_t size,
                           size_t alignment) {
    UMF_CHECK((hPool != NULL), NULL);
    return hPool->ops.aligned_malloc(hPool->pool_priv, size, alignment);
}

void *umfPoolCalloc(umf_memory_pool_handle_t hPool, size_t num, size_t size) {
    UMF_CHECK((hPool != NULL), NULL);
    return hPool->ops.calloc(hPool->pool_priv, num, size);
}

void *umfPoolRealloc(umf_memory_pool_handle_t hPool, void *ptr, size_t size) {
    UMF_CHECK((hPool != NULL), NULL);
    return hPool->ops.realloc(hPool->pool_priv, ptr, size);
}

size_t umfPoolMallocUsableSize(umf_memory_pool_handle_t hPool, void *ptr) {
    UMF_CHECK((hPool != NULL), 0);
    return hPool->ops.malloc_usable_size(hPool->pool_priv, ptr);
}

umf_result_t umfPoolFree(umf_memory_pool_handle_t hPool, void *ptr) {
    UMF_CHECK((hPool != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    return hPool->ops.free(hPool->pool_priv, ptr);
}

umf_result_t umfPoolGetLastAllocationError(umf_memory_pool_handle_t hPool) {
    UMF_CHECK((hPool != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    return hPool->ops.get_last_allocation_error(hPool->pool_priv);
}

umf_result_t umfPoolSetTag(umf_memory_pool_handle_t hPool, void *tag,
                           void **oldTag) {
    UMF_CHECK((hPool != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    utils_mutex_lock(&hPool->lock);
    if (oldTag) {
        *oldTag = hPool->tag;
    }
    hPool->tag = tag;
    utils_mutex_unlock(&hPool->lock);
    return UMF_RESULT_SUCCESS;
}

umf_result_t umfPoolGetTag(umf_memory_pool_handle_t hPool, void **tag) {
    UMF_CHECK((hPool != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((tag != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    utils_mutex_lock(&hPool->lock);
    *tag = hPool->tag;
    utils_mutex_unlock(&hPool->lock);
    return UMF_RESULT_SUCCESS;
}
