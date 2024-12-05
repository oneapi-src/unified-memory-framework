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

#include <umf/ipc.h>

#include "base_alloc_global.h"
#include "ipc_internal.h"
#include "memory_pool_internal.h"
#include "provider/provider_tracking.h"
#include "utils_common.h"
#include "utils_log.h"

umf_result_t umfPoolGetIPCHandleSize(umf_memory_pool_handle_t hPool,
                                     size_t *size) {
    umf_result_t ret = UMF_RESULT_SUCCESS;
    if (hPool == NULL) {
        LOG_ERR("pool handle is NULL.");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (size == NULL) {
        LOG_ERR("size is NULL.");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    // We cannot use umfPoolGetMemoryProvider function because it returns
    // upstream provider but we need tracking one
    umf_memory_provider_handle_t hProvider = hPool->provider;
    assert(hProvider);

    size_t providerIPCHandleSize;
    ret = umfMemoryProviderGetIPCHandleSize(hProvider, &providerIPCHandleSize);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("cannot get IPC handle size.");
        return ret;
    }

    *size = sizeof(umf_ipc_data_t) + providerIPCHandleSize;

    return ret;
}

umf_result_t umfGetIPCHandle(const void *ptr, umf_ipc_handle_t *umfIPCHandle,
                             size_t *size) {
    if (ptr == NULL || umfIPCHandle == NULL || size == NULL) {
        LOG_ERR("invalid argument.");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    size_t ipcHandleSize = 0;
    umf_alloc_info_t allocInfo;
    umf_result_t ret = umfMemoryTrackerGetAllocInfo(ptr, &allocInfo);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("cannot get alloc info for ptr = %p.", ptr);
        return ret;
    }

    ret = umfPoolGetIPCHandleSize(allocInfo.pool, &ipcHandleSize);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("cannot get IPC handle size.");
        return ret;
    }

    umf_ipc_data_t *ipcData = umf_ba_global_alloc(ipcHandleSize);
    if (!ipcData) {
        LOG_ERR("failed to allocate ipcData");
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    // We cannot use umfPoolGetMemoryProvider function because it returns
    // upstream provider but we need tracking one
    umf_memory_provider_handle_t provider = allocInfo.pool->provider;
    assert(provider);

    ret = umfMemoryProviderGetIPCHandle(provider, allocInfo.base,
                                        allocInfo.baseSize,
                                        (void *)ipcData->providerIpcData);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("failed to get IPC handle.");
        umf_ba_global_free(ipcData);
        return ret;
    }

    // ipcData->handle_id is filled by tracking provider
    ipcData->base = allocInfo.base;
    ipcData->pid = utils_getpid();
    ipcData->baseSize = allocInfo.baseSize;
    ipcData->offset = (uintptr_t)ptr - (uintptr_t)allocInfo.base;

    *umfIPCHandle = ipcData;
    *size = ipcHandleSize;

    return ret;
}

umf_result_t umfPutIPCHandle(umf_ipc_handle_t umfIPCHandle) {
    umf_result_t ret = UMF_RESULT_SUCCESS;

    // TODO: Just return SUCCESS because current tracking memory provider
    //       implementation does nothing in Put function. Tracking memory
    //       provider relies on IPC cache and actually Put IPC handle back
    //       to upstream memory provider when umfMemoryProviderFree is called.
    //       To support encapsulation we should not take into account
    //       implementation details of tracking memory provider and find the
    //       appropriate pool, get memory provider of that pool and call
    //       umfMemoryProviderPutIPCHandle(hProvider,
    //                                     umfIPCHandle->providerIpcData);
    umf_ba_global_free(umfIPCHandle);

    return ret;
}

umf_result_t umfOpenIPCHandle(umf_ipc_handler_handle_t hIPCHandler,
                              umf_ipc_handle_t umfIPCHandle, void **ptr) {

    // IPC handler is an instance of tracking memory provider
    if (*(uint32_t *)hIPCHandler != UMF_VERSION_CURRENT) {
        // It is a temporary hack to verify that user passes correct IPC handler,
        // not a pool handle, as it was required in previous version.
        LOG_ERR("Invalid IPC handler.");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_memory_provider_handle_t hProvider = hIPCHandler;
    void *base = NULL;

    umf_result_t ret = umfMemoryProviderOpenIPCHandle(
        hProvider, (void *)umfIPCHandle->providerIpcData, &base);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("memory provider failed to open the IPC handle.");
        return ret;
    }
    *ptr = (void *)((uintptr_t)base + umfIPCHandle->offset);

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfCloseIPCHandle(void *ptr) {
    umf_alloc_info_t allocInfo;
    umf_result_t ret = umfMemoryTrackerGetAllocInfo(ptr, &allocInfo);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("cannot get alloc info for ptr = %p.", ptr);
        return ret;
    }

    // We cannot use umfPoolGetMemoryProvider function because it returns
    // upstream provider but we need tracking one
    umf_memory_provider_handle_t hProvider = allocInfo.pool->provider;

    return umfMemoryProviderCloseIPCHandle(hProvider, allocInfo.base,
                                           allocInfo.baseSize);
}

umf_result_t umfPoolGetIPCHandler(umf_memory_pool_handle_t hPool,
                                  umf_ipc_handler_handle_t *hIPCHandler) {
    if (hPool == NULL) {
        LOG_ERR("Pool handle is NULL.");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (hIPCHandler == NULL) {
        LOG_ERR("hIPCHandler is NULL.");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    // We cannot use umfPoolGetMemoryProvider function because it returns
    // upstream provider but we need tracking one
    umf_memory_provider_handle_t hProvider = hPool->provider;

    // We are using tracking provider as an IPC handler because
    // it is doing IPC caching.
    *hIPCHandler = (umf_ipc_handler_handle_t)hProvider;

    return UMF_RESULT_SUCCESS;
}
