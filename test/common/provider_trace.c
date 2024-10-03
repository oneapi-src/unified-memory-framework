// Copyright (C) 2023-2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <assert.h>
#include <stdlib.h>

#include "provider_trace.h"
#include <umf/memory_provider.h>
#include <umf/memory_provider_ops.h>

static umf_result_t traceInitialize(void *params, void **pool) {
    umf_provider_trace_params_t *trace_pool =
        (umf_provider_trace_params_t *)malloc(
            sizeof(umf_provider_trace_params_t));
    if (NULL == trace_pool) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    umf_provider_trace_params_t *pub_params = params;
    trace_pool->hUpstreamProvider = pub_params->hUpstreamProvider;
    trace_pool->own_upstream = pub_params->own_upstream;
    trace_pool->trace_context = pub_params->trace_context;
    trace_pool->trace_handler = pub_params->trace_handler;

    *pool = trace_pool;

    return UMF_RESULT_SUCCESS;
}

static void traceFinalize(void *provider) {
    umf_provider_trace_params_t *traceProvider =
        (umf_provider_trace_params_t *)provider;
    if (traceProvider->own_upstream) {
        umfMemoryProviderDestroy(traceProvider->hUpstreamProvider);
    }
    free(provider);
}

static umf_result_t traceAlloc(void *provider, size_t size, size_t alignment,
                               void **ptr) {
    umf_provider_trace_params_t *traceProvider =
        (umf_provider_trace_params_t *)provider;

    traceProvider->trace_handler(traceProvider->trace_context, "alloc");
    return umfMemoryProviderAlloc(traceProvider->hUpstreamProvider, size,
                                  alignment, ptr);
}

static umf_result_t traceFree(void *provider, void *ptr, size_t size) {
    umf_provider_trace_params_t *traceProvider =
        (umf_provider_trace_params_t *)provider;

    traceProvider->trace_handler(traceProvider->trace_context, "free");
    return umfMemoryProviderFree(traceProvider->hUpstreamProvider, ptr, size);
}

static void traceGetLastError(void *provider, const char **ppMsg,
                              int32_t *pError) {
    umf_provider_trace_params_t *traceProvider =
        (umf_provider_trace_params_t *)provider;

    traceProvider->trace_handler(traceProvider->trace_context,
                                 "get_last_native_error");
    umfMemoryProviderGetLastNativeError(traceProvider->hUpstreamProvider, ppMsg,
                                        pError);
}

static umf_result_t traceGetRecommendedPageSize(void *provider, size_t size,
                                                size_t *pageSize) {
    umf_provider_trace_params_t *traceProvider =
        (umf_provider_trace_params_t *)provider;

    traceProvider->trace_handler(traceProvider->trace_context,
                                 "get_recommended_page_size");
    return umfMemoryProviderGetRecommendedPageSize(
        traceProvider->hUpstreamProvider, size, pageSize);
}

static umf_result_t traceGetPageSize(void *provider, void *ptr,

                                     size_t *pageSize) {
    umf_provider_trace_params_t *traceProvider =
        (umf_provider_trace_params_t *)provider;

    traceProvider->trace_handler(traceProvider->trace_context,
                                 "get_min_page_size");
    return umfMemoryProviderGetMinPageSize(traceProvider->hUpstreamProvider,
                                           ptr, pageSize);
}

static const char *traceName(void *provider) {
    umf_provider_trace_params_t *traceProvider =
        (umf_provider_trace_params_t *)provider;

    traceProvider->trace_handler(traceProvider->trace_context, "name");
    return umfMemoryProviderGetName(traceProvider->hUpstreamProvider);
}

static umf_result_t tracePurgeLazy(void *provider, void *ptr, size_t size) {
    umf_provider_trace_params_t *traceProvider =
        (umf_provider_trace_params_t *)provider;

    traceProvider->trace_handler(traceProvider->trace_context, "purge_lazy");
    return umfMemoryProviderPurgeLazy(traceProvider->hUpstreamProvider, ptr,
                                      size);
}

static umf_result_t tracePurgeForce(void *provider, void *ptr, size_t size) {
    umf_provider_trace_params_t *traceProvider =
        (umf_provider_trace_params_t *)provider;

    traceProvider->trace_handler(traceProvider->trace_context, "purge_force");
    return umfMemoryProviderPurgeForce(traceProvider->hUpstreamProvider, ptr,
                                       size);
}

static umf_result_t traceAllocationMerge(void *provider, void *lowPtr,
                                         void *highPtr, size_t totalSize) {
    umf_provider_trace_params_t *traceProvider =
        (umf_provider_trace_params_t *)provider;

    traceProvider->trace_handler(traceProvider->trace_context,
                                 "allocation_merge");
    return umfMemoryProviderAllocationMerge(traceProvider->hUpstreamProvider,
                                            lowPtr, highPtr, totalSize);
}

static umf_result_t traceAllocationSplit(void *provider, void *ptr,
                                         size_t totalSize, size_t firstSize) {
    umf_provider_trace_params_t *traceProvider =
        (umf_provider_trace_params_t *)provider;

    traceProvider->trace_handler(traceProvider->trace_context,
                                 "allocation_split");
    return umfMemoryProviderAllocationSplit(traceProvider->hUpstreamProvider,
                                            ptr, totalSize, firstSize);
}

static umf_result_t traceGetIpcHandleSize(void *provider, size_t *pSize) {
    umf_provider_trace_params_t *traceProvider =
        (umf_provider_trace_params_t *)provider;

    traceProvider->trace_handler(traceProvider->trace_context,
                                 "get_ipc_handle_size");
    return umfMemoryProviderGetIPCHandleSize(traceProvider->hUpstreamProvider,
                                             pSize);
}

static umf_result_t traceGetIpcHandle(void *provider, const void *ptr,
                                      size_t size, void *ipcHandle) {
    umf_provider_trace_params_t *traceProvider =
        (umf_provider_trace_params_t *)provider;

    traceProvider->trace_handler(traceProvider->trace_context,
                                 "get_ipc_handle");
    return umfMemoryProviderGetIPCHandle(traceProvider->hUpstreamProvider, ptr,
                                         size, ipcHandle);
}

static umf_result_t tracePutIpcHandle(void *provider, void *ipcHandle) {
    umf_provider_trace_params_t *traceProvider =
        (umf_provider_trace_params_t *)provider;

    traceProvider->trace_handler(traceProvider->trace_context,
                                 "put_ipc_handle");
    return umfMemoryProviderPutIPCHandle(traceProvider->hUpstreamProvider,
                                         ipcHandle);
}

static umf_result_t traceOpenIpcHandle(void *provider, void *ipcHandle,
                                       void **ptr) {
    umf_provider_trace_params_t *traceProvider =
        (umf_provider_trace_params_t *)provider;

    traceProvider->trace_handler(traceProvider->trace_context,
                                 "open_ipc_handle");
    return umfMemoryProviderOpenIPCHandle(traceProvider->hUpstreamProvider,
                                          ipcHandle, ptr);
}

static umf_result_t traceCloseIpcHandle(void *provider, void *ptr,
                                        size_t size) {
    umf_provider_trace_params_t *traceProvider =
        (umf_provider_trace_params_t *)provider;

    traceProvider->trace_handler(traceProvider->trace_context,
                                 "close_ipc_handle");
    return umfMemoryProviderCloseIPCHandle(traceProvider->hUpstreamProvider,
                                           ptr, size);
}

umf_memory_provider_ops_t UMF_TRACE_PROVIDER_OPS = {
    .version = UMF_VERSION_CURRENT,
    .initialize = traceInitialize,
    .finalize = traceFinalize,
    .alloc = traceAlloc,
    .get_last_native_error = traceGetLastError,
    .get_recommended_page_size = traceGetRecommendedPageSize,
    .get_min_page_size = traceGetPageSize,
    .get_name = traceName,
    .ext.free = traceFree,
    .ext.purge_lazy = tracePurgeLazy,
    .ext.purge_force = tracePurgeForce,
    .ext.allocation_merge = traceAllocationMerge,
    .ext.allocation_split = traceAllocationSplit,
    .ipc.get_ipc_handle_size = traceGetIpcHandleSize,
    .ipc.get_ipc_handle = traceGetIpcHandle,
    .ipc.put_ipc_handle = tracePutIpcHandle,
    .ipc.open_ipc_handle = traceOpenIpcHandle,
    .ipc.close_ipc_handle = traceCloseIpcHandle,
};
