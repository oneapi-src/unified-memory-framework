/*
 * Copyright (C) 2024-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <umf.h>
#include <umf/memory_provider_ops.h>
#include <umf/providers/provider_fixed_memory.h>

#include "base_alloc_global.h"
#include "coarse.h"
#include "libumf.h"
#include "memory_pool_internal.h"
#include "provider_tracking.h"
#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_log.h"

#define TLS_MSG_BUF_LEN 1024

typedef struct fixed_memory_provider_t {
    void *base;         // base address of memory
    size_t size;        // size of the memory region
    unsigned int flags; // flags of the memory region
    coarse_t *coarse;   // coarse library handle

    // used only when the UMF_FIXED_FLAG_CREATE_FROM_POOL_PTR flag is set
    size_t ptr_orig_size; // original size of the memory region in the tracker
    umf_memory_provider_handle_t
        trackingProvider; // tracking provider of the original memory pool
} fixed_memory_provider_t;

// Fixed Memory provider settings struct
typedef struct umf_fixed_memory_provider_params_t {
    void *ptr;
    size_t size;
    unsigned int flags;
} umf_fixed_memory_provider_params_t;

typedef struct fixed_last_native_error_t {
    int32_t native_error;
    int errno_value;
    char msg_buff[TLS_MSG_BUF_LEN];
} fixed_last_native_error_t;

static __TLS fixed_last_native_error_t TLS_last_native_error;

// helper values used only in the Native_error_str array
#define _UMF_FIXED_RESULT_SUCCESS                                              \
    (UMF_FIXED_RESULT_SUCCESS - UMF_FIXED_RESULT_SUCCESS)
#define _UMF_FIXED_RESULT_ERROR_PURGE_FORCE_FAILED                             \
    (UMF_FIXED_RESULT_ERROR_PURGE_FORCE_FAILED - UMF_FIXED_RESULT_SUCCESS)

static const char *Native_error_str[] = {
    [_UMF_FIXED_RESULT_SUCCESS] = "success",
    [_UMF_FIXED_RESULT_ERROR_PURGE_FORCE_FAILED] = "force purging failed"};

static void fixed_store_last_native_error(int32_t native_error,
                                          int errno_value) {
    TLS_last_native_error.native_error = native_error;
    TLS_last_native_error.errno_value = errno_value;
}

static umf_result_t fixed_allocation_split_cb(void *provider, void *ptr,
                                              size_t totalSize,
                                              size_t firstSize) {
    (void)provider;
    (void)ptr;
    (void)totalSize;
    (void)firstSize;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t fixed_allocation_merge_cb(void *provider, void *lowPtr,
                                              void *highPtr, size_t totalSize) {
    (void)provider;
    (void)lowPtr;
    (void)highPtr;
    (void)totalSize;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t fixed_initialize(void *params, void **provider) {
    umf_result_t ret;
    size_t ptr_orig_size = 0;
    umf_memory_provider_handle_t trackingProvider = NULL;

    if (params == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_fixed_memory_provider_params_t *in_params =
        (umf_fixed_memory_provider_params_t *)params;

    if (in_params->flags & UMF_FIXED_FLAG_CREATE_FROM_POOL_PTR) {
        umf_memory_pool_handle_t pool = umfPoolByPtr(in_params->ptr);
        if (pool == NULL) {
            LOG_ERR("The UMF_FIXED_FLAG_CREATE_FROM_POOL_PTR flag is set, but "
                    "the given pointer does not belong to any UMF pool");
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }

        ret = umfPoolGetTrackingProvider(pool, &trackingProvider);
        if (ret != UMF_RESULT_SUCCESS) {
            LOG_ERR("cannot get the tracking provider of the pool %p", pool);
            return ret;
        }

        ret = trackerShrinkEntry(trackingProvider, in_params->ptr,
                                 in_params->size, &ptr_orig_size);
        if (ret != UMF_RESULT_SUCCESS) {
            LOG_ERR(
                "cannot shrink the allocation %p in the tracker to size %zu",
                in_params->ptr, in_params->size);
            return ret;
        }
    }

    fixed_memory_provider_t *fixed_provider =
        umf_ba_global_alloc(sizeof(*fixed_provider));
    if (!fixed_provider) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    memset(fixed_provider, 0, sizeof(*fixed_provider));

    coarse_params_t coarse_params = {0};
    coarse_params.provider = fixed_provider;
    coarse_params.page_size = utils_get_page_size();
    // The alloc callback is not available in case of the fixed provider
    // because it is a fixed-size memory provider
    // and the entire memory is added as a single block
    // to the coarse library.
    coarse_params.cb.alloc = NULL;
    coarse_params.cb.free = NULL; // not available for the fixed provider
    coarse_params.cb.split = fixed_allocation_split_cb;
    coarse_params.cb.merge = fixed_allocation_merge_cb;

    coarse_t *coarse = NULL;
    ret = coarse_new(&coarse_params, &coarse);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("coarse_new() failed");
        goto err_free_fixed_provider;
    }

    fixed_provider->coarse = coarse;

    fixed_provider->base = in_params->ptr;
    fixed_provider->size = in_params->size;
    fixed_provider->flags = in_params->flags;
    fixed_provider->ptr_orig_size = ptr_orig_size;
    fixed_provider->trackingProvider = trackingProvider;

    // add the entire memory as a single block
    ret = coarse_add_memory_fixed(coarse, fixed_provider->base,
                                  fixed_provider->size);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("adding memory block failed");
        goto err_coarse_delete;
    }

    *provider = fixed_provider;

    return UMF_RESULT_SUCCESS;

err_coarse_delete:
    coarse_delete(fixed_provider->coarse);
err_free_fixed_provider:
    umf_ba_global_free(fixed_provider);
    return ret;
}

static void fixed_finalize(void *provider) {
    fixed_memory_provider_t *fixed_provider = provider;
    coarse_delete(fixed_provider->coarse);

    if (fixed_provider->trackingProvider &&
        (fixed_provider->ptr_orig_size >= fixed_provider->size)) {
        umf_result_t ret = trackerGrowEntry(
            fixed_provider->trackingProvider, fixed_provider->base,
            fixed_provider->size, fixed_provider->ptr_orig_size);
        if (ret != UMF_RESULT_SUCCESS) {
            LOG_ERR("cannot grow the allocation %p in the tracker (from size "
                    "%zu to size %zu)",
                    fixed_provider->base, fixed_provider->size,
                    fixed_provider->ptr_orig_size);
        }
    }

    umf_ba_global_free(fixed_provider);
}

static umf_result_t fixed_alloc(void *provider, size_t size, size_t alignment,
                                void **resultPtr) {
    fixed_memory_provider_t *fixed_provider =
        (fixed_memory_provider_t *)provider;

    return coarse_alloc(fixed_provider->coarse, size, alignment, resultPtr);
}

static void fixed_get_last_native_error(void *provider, const char **ppMessage,
                                        int32_t *pError) {
    (void)provider; // unused

    if (ppMessage == NULL || pError == NULL) {
        assert(0);
        return;
    }

    *pError = TLS_last_native_error.native_error;
    if (TLS_last_native_error.errno_value == 0) {
        *ppMessage = Native_error_str[*pError - UMF_FIXED_RESULT_SUCCESS];
        return;
    }

    const char *msg;
    size_t len;
    size_t pos = 0;

    msg = Native_error_str[*pError - UMF_FIXED_RESULT_SUCCESS];
    len = strlen(msg);
    memcpy(TLS_last_native_error.msg_buff + pos, msg, len + 1);
    pos += len;

    msg = ": ";
    len = strlen(msg);
    memcpy(TLS_last_native_error.msg_buff + pos, msg, len + 1);
    pos += len;

    utils_strerror(TLS_last_native_error.errno_value,
                   TLS_last_native_error.msg_buff + pos, TLS_MSG_BUF_LEN - pos);

    *ppMessage = TLS_last_native_error.msg_buff;
}

static umf_result_t fixed_get_recommended_page_size(void *provider, size_t size,
                                                    size_t *page_size) {
    (void)provider; // unused
    (void)size;     // unused

    *page_size = utils_get_page_size();

    return UMF_RESULT_SUCCESS;
}

static umf_result_t fixed_get_min_page_size(void *provider, void *ptr,
                                            size_t *page_size) {
    (void)ptr; // unused

    return fixed_get_recommended_page_size(provider, 0, page_size);
}

static umf_result_t fixed_purge_lazy(void *provider, void *ptr, size_t size) {
    (void)provider; // unused
    (void)ptr;      // unused
    (void)size;     // unused
    // purge_lazy is unsupported in case of the fixed memory provider
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

static umf_result_t fixed_purge_force(void *provider, void *ptr, size_t size) {
    (void)provider; // unused
    errno = 0;
    if (utils_purge(ptr, size, UMF_PURGE_FORCE)) {
        fixed_store_last_native_error(UMF_FIXED_RESULT_ERROR_PURGE_FORCE_FAILED,
                                      errno);
        LOG_PERR("force purging failed");
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }
    return UMF_RESULT_SUCCESS;
}

static const char *fixed_get_name(void *provider) {
    (void)provider; // unused
    return "FIXED";
}

static umf_result_t fixed_allocation_split(void *provider, void *ptr,
                                           size_t totalSize, size_t firstSize) {
    fixed_memory_provider_t *fixed_provider =
        (fixed_memory_provider_t *)provider;
    return coarse_split(fixed_provider->coarse, ptr, totalSize, firstSize);
}

static umf_result_t fixed_allocation_merge(void *provider, void *lowPtr,
                                           void *highPtr, size_t totalSize) {
    fixed_memory_provider_t *fixed_provider =
        (fixed_memory_provider_t *)provider;
    return coarse_merge(fixed_provider->coarse, lowPtr, highPtr, totalSize);
}

static umf_result_t fixed_free(void *provider, void *ptr, size_t size) {
    fixed_memory_provider_t *fixed_provider =
        (fixed_memory_provider_t *)provider;
    return coarse_free(fixed_provider->coarse, ptr, size);
}

static umf_memory_provider_ops_t UMF_FIXED_MEMORY_PROVIDER_OPS = {
    .version = UMF_PROVIDER_OPS_VERSION_CURRENT,
    .initialize = fixed_initialize,
    .finalize = fixed_finalize,
    .alloc = fixed_alloc,
    .free = fixed_free,
    .get_last_native_error = fixed_get_last_native_error,
    .get_recommended_page_size = fixed_get_recommended_page_size,
    .get_min_page_size = fixed_get_min_page_size,
    .get_name = fixed_get_name,
    .ext.purge_lazy = fixed_purge_lazy,
    .ext.purge_force = fixed_purge_force,
    .ext.allocation_merge = fixed_allocation_merge,
    .ext.allocation_split = fixed_allocation_split,
    .ipc.get_ipc_handle_size = NULL,
    .ipc.get_ipc_handle = NULL,
    .ipc.put_ipc_handle = NULL,
    .ipc.open_ipc_handle = NULL,
    .ipc.close_ipc_handle = NULL};

umf_memory_provider_ops_t *umfFixedMemoryProviderOps(void) {
    return &UMF_FIXED_MEMORY_PROVIDER_OPS;
}

umf_result_t umfFixedMemoryProviderParamsCreate(
    umf_fixed_memory_provider_params_handle_t *hParams, void *ptr,
    size_t size) {
    libumfInit();
    if (hParams == NULL) {
        LOG_ERR("Memory Provider params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_fixed_memory_provider_params_handle_t params =
        umf_ba_global_alloc(sizeof(*params));
    if (params == NULL) {
        LOG_ERR("Allocating memory for the Memory Provider params failed");
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    umf_result_t ret = umfFixedMemoryProviderParamsSetMemory(params, ptr, size);
    if (ret != UMF_RESULT_SUCCESS) {
        umf_ba_global_free(params);
        return ret;
    }

    *hParams = params;

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfFixedMemoryProviderParamsDestroy(
    umf_fixed_memory_provider_params_handle_t hParams) {
    if (hParams != NULL) {
        umf_ba_global_free(hParams);
    }

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfFixedMemoryProviderParamsSetMemory(
    umf_fixed_memory_provider_params_handle_t hParams, void *ptr, size_t size) {

    if (hParams == NULL) {
        LOG_ERR("Memory Provider params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (ptr == NULL) {
        LOG_ERR("Memory pointer is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (size == 0) {
        LOG_ERR("Size must be greater than 0");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hParams->ptr = ptr;
    hParams->size = size;
    hParams->flags = 0;

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfFixedMemoryProviderParamsSetFlags(
    umf_fixed_memory_provider_params_handle_t hParams, unsigned int flags) {
    if (hParams == NULL) {
        LOG_ERR("Memory Provider params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if ((flags & UMF_FIXED_FLAG_CREATE_FROM_POOL_PTR) &&
        (umfPoolByPtr(hParams->ptr) == NULL)) {
        LOG_ERR("Cannot set the UMF_FIXED_FLAG_CREATE_FROM_POOL_PTR, because "
                "the given pointer does not belong to any UMF pool");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hParams->flags = flags;

    return UMF_RESULT_SUCCESS;
}
