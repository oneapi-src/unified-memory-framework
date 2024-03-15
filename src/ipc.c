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

#include "umf/ipc.h"

#include "base_alloc_global.h"
#include "ipc_internal.h"
#include "memory_pool_internal.h"
#include "provider/provider_tracking.h"

umf_result_t umfGetIPCHandle(const void *ptr, umf_ipc_handle_t *umfIPCHandle,
                             size_t *size) {
    size_t ipcHandleSize = 0;
    umf_alloc_info_t allocInfo;
    umf_result_t ret = umfMemoryTrackerGetAllocInfo(ptr, &allocInfo);
    if (ret != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "umfGetIPCHandle: cannot get alloc info for ptr = %p\n",
                ptr);
        return ret;
    }

    // We cannot use umfPoolGetMemoryProvider function because it returns
    // upstream provider but we need tracking one
    umf_memory_provider_handle_t provider = allocInfo.pool->provider;
    assert(provider);

    size_t providerIPCHandleSize;
    ret = umfMemoryProviderGetIPCHandleSize(provider, &providerIPCHandleSize);
    if (ret != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "umfGetIPCHandle: cannot get IPC handle size\n");
        return ret;
    }

    ipcHandleSize = sizeof(umf_ipc_data_t) + providerIPCHandleSize;
    umf_ipc_data_t *ipcData = umf_ba_global_alloc(ipcHandleSize);
    if (!ipcData) {
        fprintf(stderr, "umfGetIPCHandle: failed to allocate ipcData\n");
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    ret =
        umfMemoryProviderGetIPCHandle(provider, allocInfo.base, allocInfo.size,
                                      (void *)ipcData->providerData);
    if (ret != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "umfGetIPCHandle: failed to get IPC handle\n");
        umf_ba_global_free(ipcData);
        return ret;
    }

    ipcData->size = allocInfo.size;
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
    //       To support incapsulation we should not take into account
    //       implementation details of tracking memory provider and find the
    //       approrpiate pool, get memory provider of that pool and call
    //       umfMemoryProviderPutIPCHandle(hProvider,
    //                                     umfIPCHandle->providerData);
    umf_ba_global_free(umfIPCHandle);

    return ret;
}

umf_result_t umfOpenIPCHandle(umf_memory_pool_handle_t hPool,
                              umf_ipc_handle_t umfIPCHandle, void **ptr) {

    // We cannot use umfPoolGetMemoryProvider function because it returns
    // upstream provider but we need tracking one
    umf_memory_provider_handle_t hProvider = hPool->provider;
    void *base = NULL;

    umf_result_t ret = umfMemoryProviderOpenIPCHandle(
        hProvider, (void *)umfIPCHandle->providerData, &base);
    if (ret != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "umfOpenIPCHandle: memory provider failed to IPC handle\n");
        return ret;
    }
    *ptr = (void *)((uintptr_t)base + umfIPCHandle->offset);

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfCloseIPCHandle(void *ptr) {
    umf_alloc_info_t allocInfo;
    umf_result_t ret = umfMemoryTrackerGetAllocInfo(ptr, &allocInfo);
    if (ret != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "umfCloseIPCHandle: cannot get alloc info for ptr = %p\n", ptr);
        return ret;
    }

    // We cannot use umfPoolGetMemoryProvider function because it returns
    // upstream provider but we need tracking one
    umf_memory_provider_handle_t hProvider = allocInfo.pool->provider;

    return umfMemoryProviderCloseIPCHandle(hProvider, allocInfo.base);
}
