// Copyright (C) 2023-2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <assert.h>
#include <stdlib.h>

#include <umf/memory_provider_ops.h>

#include "provider_null.h"
#include "utils_common.h"

static umf_result_t nullInitialize(const void *params, void **pool) {
    (void)params;
    *pool = NULL;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t nullFinalize(void *pool) {
    (void)pool;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t nullAlloc(void *provider, size_t size, size_t alignment,
                              void **ptr) {
    (void)provider;

    if (ptr == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (size == 0) {
        *ptr = NULL;
        return UMF_RESULT_SUCCESS;
    }

    *ptr = (void *)ALIGN_UP_SAFE(0xDEADBEAF, alignment); // any not-NULL value

    return UMF_RESULT_SUCCESS;
}

static umf_result_t nullFree(void *provider, void *ptr, size_t size) {
    (void)provider;
    (void)ptr;
    (void)size;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t nullGetLastError(void *provider, const char **ppMsg,
                                     int32_t *pError) {
    (void)provider;
    (void)ppMsg;
    (void)pError;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t nullGetRecommendedPageSize(void *provider, size_t size,
                                               size_t *pageSize) {
    (void)provider;
    (void)size;
    (void)pageSize;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t nullGetPageSize(void *provider, const void *ptr,
                                    size_t *pageSize) {
    (void)provider;
    (void)ptr;
    (void)pageSize;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t nullName(void *provider, const char **name) {
    (void)provider;
    *name = "null";
    return UMF_RESULT_SUCCESS;
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

static umf_result_t
nullGetAllocationProperties(void *provider, const void *ptr,
                            umf_memory_property_id_t propertyId, void *value) {
    (void)provider;
    (void)ptr;
    (void)propertyId;
    (void)value;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t nullGetAllocationPropertiesSize(
    void *provider, umf_memory_property_id_t propertyId, size_t *size) {
    (void)provider;
    (void)propertyId;
    (void)size;
    return UMF_RESULT_SUCCESS;
}

umf_memory_provider_ops_t UMF_NULL_PROVIDER_OPS = {
    .version = UMF_PROVIDER_OPS_VERSION_CURRENT,
    .initialize = nullInitialize,
    .finalize = nullFinalize,
    .alloc = nullAlloc,
    .free = nullFree,
    .get_last_native_error = nullGetLastError,
    .get_recommended_page_size = nullGetRecommendedPageSize,
    .get_min_page_size = nullGetPageSize,
    .get_name = nullName,
    .ext_purge_lazy = nullPurgeLazy,
    .ext_purge_force = nullPurgeForce,
    .ext_allocation_merge = nullAllocationMerge,
    .ext_allocation_split = nullAllocationSplit,
    .ext_get_ipc_handle_size = nullGetIpcHandleSize,
    .ext_get_ipc_handle = nullGetIpcHandle,
    .ext_put_ipc_handle = nullPutIpcHandle,
    .ext_open_ipc_handle = nullOpenIpcHandle,
    .ext_close_ipc_handle = nullCloseIpcHandle,
    .ext_get_allocation_properties = nullGetAllocationProperties,
    .ext_get_allocation_properties_size = nullGetAllocationPropertiesSize,
};
