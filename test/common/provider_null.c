// Copyright (C) 2023-2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <assert.h>
#include <stdlib.h>

#include "provider_null.h"
#include <umf/memory_provider_ops.h>

static umf_result_t nullInitialize(void *params, void **pool) {
    (void)params;
    *pool = NULL;
    return UMF_RESULT_SUCCESS;
}

static void nullFinalize(void *pool) { (void)pool; }

static umf_result_t nullAlloc(void *provider, size_t size, size_t alignment,
                              void **ptr) {
    (void)provider;
    (void)size;
    (void)alignment;
    *ptr = NULL;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t nullFree(void *provider, void *ptr, size_t size) {
    (void)provider;
    (void)ptr;
    (void)size;
    return UMF_RESULT_SUCCESS;
}

static void nullGetLastError(void *provider, const char **ppMsg,
                             int32_t *pError) {
    (void)provider;
    (void)ppMsg;
    (void)pError;
}

static umf_result_t nullGetRecommendedPageSize(void *provider, size_t size,
                                               size_t *pageSize) {
    (void)provider;
    (void)size;
    (void)pageSize;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t nullGetPageSize(void *provider, void *ptr,

                                    size_t *pageSize) {
    (void)provider;
    (void)ptr;
    (void)pageSize;
    return UMF_RESULT_SUCCESS;
}

static const char *nullName(void *provider) {
    (void)provider;
    return "null";
}

static umf_result_t nullPurgeLazy(void *provider, void *ptr, size_t size) {
    (void)provider;
    (void)ptr;
    (void)size;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t nullPurgeForce(void *provider, void *ptr, size_t size) {
    (void)provider;
    (void)ptr;
    (void)size;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t nullAllocationMerge(void *provider, void *lowPtr,
                                        void *highPtr, size_t totalSize) {
    (void)provider;
    (void)lowPtr;
    (void)highPtr;
    (void)totalSize;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t nullAllocationSplit(void *provider, void *ptr,
                                        size_t totalSize, size_t firstSize) {
    (void)provider;
    (void)ptr;
    (void)totalSize;
    (void)firstSize;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t nullGetIpcHandleSize(void *provider, size_t *size) {
    (void)provider;
    (void)size;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t nullGetIpcHandle(void *provider, const void *ptr,
                                     size_t size, void *ipcHandle) {
    (void)provider;
    (void)ptr;
    (void)size;
    (void)ipcHandle;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t nullPutIpcHandle(void *provider, void *ipcHandle) {
    (void)provider;
    (void)ipcHandle;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t nullOpenIpcHandle(void *provider, void *ipcHandle,
                                      void **ptr) {
    (void)provider;
    (void)ipcHandle;
    (void)ptr;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t nullCloseIpcHandle(void *provider, void *ptr, size_t size) {
    (void)provider;
    (void)ptr;
    (void)size;
    return UMF_RESULT_SUCCESS;
}

umf_memory_provider_ops_t UMF_NULL_PROVIDER_OPS = {
    .version = UMF_VERSION_CURRENT,
    .initialize = nullInitialize,
    .finalize = nullFinalize,
    .alloc = nullAlloc,
    .get_last_native_error = nullGetLastError,
    .get_recommended_page_size = nullGetRecommendedPageSize,
    .get_min_page_size = nullGetPageSize,
    .get_name = nullName,
    .ext.free = nullFree,
    .ext.purge_lazy = nullPurgeLazy,
    .ext.purge_force = nullPurgeForce,
    .ext.allocation_merge = nullAllocationMerge,
    .ext.allocation_split = nullAllocationSplit,
    .ipc.get_ipc_handle_size = nullGetIpcHandleSize,
    .ipc.get_ipc_handle = nullGetIpcHandle,
    .ipc.put_ipc_handle = nullPutIpcHandle,
    .ipc.open_ipc_handle = nullOpenIpcHandle,
    .ipc.close_ipc_handle = nullCloseIpcHandle,
};
