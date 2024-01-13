/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "memory_provider_internal.h"
#include <umf/memory_provider.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct umf_memory_provider_t {
    umf_memory_provider_ops_t ops;
    void *provider_priv;
} umf_memory_provider_t;

umf_result_t umfMemoryProviderCreate(const umf_memory_provider_ops_t *ops,
                                     void *params,
                                     umf_memory_provider_handle_t *hProvider) {
    if (!ops || !hProvider) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_memory_provider_handle_t provider =
        malloc(sizeof(umf_memory_provider_t));
    if (!provider) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    assert(ops->version == UMF_VERSION_CURRENT);

    provider->ops = *ops;

    void *provider_priv;
    umf_result_t ret = ops->initialize(params, &provider_priv);
    if (ret != UMF_RESULT_SUCCESS) {
        free(provider);
        return ret;
    }

    provider->provider_priv = provider_priv;

    *hProvider = provider;

    return UMF_RESULT_SUCCESS;
}

void umfMemoryProviderDestroy(umf_memory_provider_handle_t hProvider) {
    hProvider->ops.finalize(hProvider->provider_priv);
    free(hProvider);
}

static void
checkErrorAndSetLastProvider(umf_result_t result,
                             umf_memory_provider_handle_t hProvider) {
    if (result != UMF_RESULT_SUCCESS) {
        *umfGetLastFailedMemoryProviderPtr() = hProvider;
    }
}

umf_result_t umfMemoryProviderAlloc(umf_memory_provider_handle_t hProvider,
                                    size_t size, size_t alignment, void **ptr) {
    umf_result_t res =
        hProvider->ops.alloc(hProvider->provider_priv, size, alignment, ptr);
    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

umf_result_t umfMemoryProviderFree(umf_memory_provider_handle_t hProvider,
                                   void *ptr, size_t size) {
    umf_result_t res = hProvider->ops.free(hProvider->provider_priv, ptr, size);
    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

void umfMemoryProviderGetLastNativeError(umf_memory_provider_handle_t hProvider,
                                         const char **ppMessage,
                                         int32_t *pError) {
    hProvider->ops.get_last_native_error(hProvider->provider_priv, ppMessage,
                                         pError);
}

void *umfMemoryProviderGetPriv(umf_memory_provider_handle_t hProvider) {
    return hProvider->provider_priv;
}

umf_result_t
umfMemoryProviderGetRecommendedPageSize(umf_memory_provider_handle_t hProvider,
                                        size_t size, size_t *pageSize) {
    umf_result_t res = hProvider->ops.get_recommended_page_size(
        hProvider->provider_priv, size, pageSize);
    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

umf_result_t
umfMemoryProviderGetMinPageSize(umf_memory_provider_handle_t hProvider,
                                void *ptr, size_t *pageSize) {
    umf_result_t res = hProvider->ops.get_min_page_size(
        hProvider->provider_priv, ptr, pageSize);
    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

umf_result_t umfMemoryProviderPurgeLazy(umf_memory_provider_handle_t hProvider,
                                        void *ptr, size_t size) {
    umf_result_t res =
        hProvider->ops.purge_lazy(hProvider->provider_priv, ptr, size);
    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

umf_result_t umfMemoryProviderPurgeForce(umf_memory_provider_handle_t hProvider,
                                         void *ptr, size_t size) {
    umf_result_t res =
        hProvider->ops.purge_force(hProvider->provider_priv, ptr, size);
    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

const char *umfMemoryProviderGetName(umf_memory_provider_handle_t hProvider) {
    return hProvider->ops.get_name(hProvider->provider_priv);
}

umf_memory_provider_handle_t umfGetLastFailedMemoryProvider(void) {
    return *umfGetLastFailedMemoryProviderPtr();
}

umf_result_t
umfMemoryProviderAllocationSplit(umf_memory_provider_handle_t hProvider,
                                 void *ptr, size_t totalSize, size_t leftSize) {
    if (leftSize >= totalSize) {
        fprintf(stderr,
                "umfMemoryProviderAllocationSplit failed. check failed: %zu >= "
                "%zu\n",
                leftSize, totalSize);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_result_t res = hProvider->ops.allocation_split(
        hProvider->provider_priv, ptr, totalSize, leftSize);
    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

umf_result_t
umfMemoryProviderAllocationMerge(umf_memory_provider_handle_t hProvider,
                                 void *leftPtr, void *rightPtr,
                                 size_t totalSize) {
    if ((uintptr_t)leftPtr >= (uintptr_t)rightPtr) {
        fprintf(
            stderr,
            "umfMemoryProviderAllocationMerge failed. check failed: %p >= %p\n",
            leftPtr, rightPtr);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if ((uintptr_t)rightPtr - (uintptr_t)leftPtr > totalSize) {
        fprintf(stderr,
                "umfMemoryProviderAllocationMerge failed. check failed: %p - "
                "%p > %zu\n",
                rightPtr, leftPtr, totalSize);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_result_t res = hProvider->ops.allocation_merge(
        hProvider->provider_priv, leftPtr, rightPtr, totalSize);
    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}
