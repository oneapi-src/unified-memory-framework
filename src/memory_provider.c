/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <umf/memory_provider.h>

#include "base_alloc.h"
#include "base_alloc_global.h"
#include "libumf.h"
#include "memory_provider_internal.h"
#include "utils_common.h"

typedef struct umf_memory_provider_t {
    umf_memory_provider_ops_t ops;
    void *provider_priv;
} umf_memory_provider_t;

static umf_result_t umfDefaultPurgeLazy(void *provider, void *ptr,
                                        size_t size) {
    (void)provider;
    (void)ptr;
    (void)size;
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

static umf_result_t umfDefaultPurgeForce(void *provider, void *ptr,
                                         size_t size) {
    (void)provider;
    (void)ptr;
    (void)size;
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

static umf_result_t umfDefaultAllocationSplit(void *provider, void *ptr,
                                              size_t totalSize,
                                              size_t firstSize) {
    (void)provider;
    (void)ptr;
    (void)totalSize;
    (void)firstSize;
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

static umf_result_t umfDefaultAllocationMerge(void *provider, void *lowPtr,
                                              void *highPtr, size_t totalSize) {
    (void)provider;
    (void)lowPtr;
    (void)highPtr;
    (void)totalSize;
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

void assignOpsExtDefaults(umf_memory_provider_ops_t *ops) {
    if (!ops->ext.purge_lazy) {
        ops->ext.purge_lazy = umfDefaultPurgeLazy;
    }
    if (!ops->ext.purge_force) {
        ops->ext.purge_force = umfDefaultPurgeForce;
    }
    if (!ops->ext.allocation_split) {
        ops->ext.allocation_split = umfDefaultAllocationSplit;
    }
    if (!ops->ext.allocation_merge) {
        ops->ext.allocation_merge = umfDefaultAllocationMerge;
    }
}

static bool validateOps(const umf_memory_provider_ops_t *ops) {
    // Mandatory ops should be non-NULL
    if (!ops->alloc || !ops->free || !ops->get_recommended_page_size ||
        !ops->get_min_page_size || !ops->initialize || !ops->finalize ||
        !ops->get_last_native_error || !ops->get_name) {
        return false;
    }

    // allocation_split and allocation_merge should be both set or both NULL
    if ((ops->ext.allocation_split && !ops->ext.allocation_merge) ||
        (!ops->ext.allocation_split && ops->ext.allocation_merge)) {
        return false;
    }

    return true;
}

umf_result_t umfMemoryProviderCreate(const umf_memory_provider_ops_t *ops,
                                     void *params,
                                     umf_memory_provider_handle_t *hProvider) {
    libumfInit();
    if (!ops || !hProvider || !validateOps(ops)) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_memory_provider_handle_t provider =
        umf_ba_global_alloc(sizeof(umf_memory_provider_t));
    if (!provider) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    assert(ops->version == UMF_VERSION_CURRENT);

    provider->ops = *ops;

    assignOpsExtDefaults(&(provider->ops));

    void *provider_priv;
    umf_result_t ret = ops->initialize(params, &provider_priv);
    if (ret != UMF_RESULT_SUCCESS) {
        umf_ba_global_free(provider);
        return ret;
    }

    provider->provider_priv = provider_priv;

    *hProvider = provider;

    return UMF_RESULT_SUCCESS;
}

void umfMemoryProviderDestroy(umf_memory_provider_handle_t hProvider) {
    hProvider->ops.finalize(hProvider->provider_priv);
    umf_ba_global_free(hProvider);
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
    UMF_CHECK((hProvider != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    umf_result_t res =
        hProvider->ops.alloc(hProvider->provider_priv, size, alignment, ptr);
    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

umf_result_t umfMemoryProviderFree(umf_memory_provider_handle_t hProvider,
                                   void *ptr, size_t size) {
    UMF_CHECK((hProvider != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    umf_result_t res = hProvider->ops.free(hProvider->provider_priv, ptr, size);
    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

void umfMemoryProviderGetLastNativeError(umf_memory_provider_handle_t hProvider,
                                         const char **ppMessage,
                                         int32_t *pError) {
    ASSERT(hProvider != NULL);
    hProvider->ops.get_last_native_error(hProvider->provider_priv, ppMessage,
                                         pError);
}

void *umfMemoryProviderGetPriv(umf_memory_provider_handle_t hProvider) {
    UMF_CHECK((hProvider != NULL), NULL);
    return hProvider->provider_priv;
}

umf_result_t
umfMemoryProviderGetRecommendedPageSize(umf_memory_provider_handle_t hProvider,
                                        size_t size, size_t *pageSize) {
    UMF_CHECK((hProvider != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    umf_result_t res = hProvider->ops.get_recommended_page_size(
        hProvider->provider_priv, size, pageSize);
    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

umf_result_t
umfMemoryProviderGetMinPageSize(umf_memory_provider_handle_t hProvider,
                                void *ptr, size_t *pageSize) {
    UMF_CHECK((hProvider != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    umf_result_t res = hProvider->ops.get_min_page_size(
        hProvider->provider_priv, ptr, pageSize);
    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

const char *umfMemoryProviderGetName(umf_memory_provider_handle_t hProvider) {
    UMF_CHECK((hProvider != NULL), NULL);
    return hProvider->ops.get_name(hProvider->provider_priv);
}

umf_result_t umfMemoryProviderPurgeLazy(umf_memory_provider_handle_t hProvider,
                                        void *ptr, size_t size) {
    UMF_CHECK((hProvider != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    umf_result_t res =
        hProvider->ops.ext.purge_lazy(hProvider->provider_priv, ptr, size);
    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

umf_result_t umfMemoryProviderPurgeForce(umf_memory_provider_handle_t hProvider,
                                         void *ptr, size_t size) {
    UMF_CHECK((hProvider != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    umf_result_t res =
        hProvider->ops.ext.purge_force(hProvider->provider_priv, ptr, size);
    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

umf_memory_provider_handle_t umfGetLastFailedMemoryProvider(void) {
    return *umfGetLastFailedMemoryProviderPtr();
}

umf_result_t
umfMemoryProviderAllocationSplit(umf_memory_provider_handle_t hProvider,
                                 void *ptr, size_t totalSize,
                                 size_t firstSize) {
    if (!ptr) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    if (firstSize == 0 || totalSize == 0) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    if (firstSize >= totalSize) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_result_t res = hProvider->ops.ext.allocation_split(
        hProvider->provider_priv, ptr, totalSize, firstSize);
    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

umf_result_t
umfMemoryProviderAllocationMerge(umf_memory_provider_handle_t hProvider,
                                 void *lowPtr, void *highPtr,
                                 size_t totalSize) {
    if (!lowPtr || !highPtr) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    if (totalSize == 0) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    if ((uintptr_t)lowPtr >= (uintptr_t)highPtr) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    if ((uintptr_t)highPtr - (uintptr_t)lowPtr > totalSize) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_result_t res = hProvider->ops.ext.allocation_merge(
        hProvider->provider_priv, lowPtr, highPtr, totalSize);
    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}
