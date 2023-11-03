// Copyright (C) 2023 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <assert.h>
#include <stdlib.h>

#include <umf/memory_provider_ops.h>
#include "provider_trace.h"

struct umf_provider_trace_params_priv {
    umf_memory_provider_handle_t hUpstreamProvider;
    void (*trace)(const char *);
};

static enum umf_result_t traceInitialize(void *params, void **pool) {
    struct umf_provider_trace_params_priv *trace_pool =
        (struct umf_provider_trace_params_priv *)malloc(sizeof(struct umf_provider_trace_params_priv));
    if (NULL == trace_pool)
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;

    struct umf_provider_trace_params *pub_params = params;
    trace_pool->hUpstreamProvider = pub_params->hUpstreamProvider;
    trace_pool->trace = pub_params->trace;

    *pool = trace_pool;

    return UMF_RESULT_SUCCESS;
}

static void traceFinalize(void *pool) { free(pool); }

static enum umf_result_t traceAlloc(void *provider, size_t size,
                                    size_t alignment, void **ptr) {
    struct umf_provider_trace_params_priv *traceProvider = (struct umf_provider_trace_params_priv *)provider;

    traceProvider->trace("alloc");
    return umfMemoryProviderAlloc(traceProvider->hUpstreamProvider, size,
                                  alignment, ptr);
}

static enum umf_result_t traceFree(void *provider, void *ptr, size_t size) {
    struct umf_provider_trace_params_priv *traceProvider = (struct umf_provider_trace_params_priv *)provider;

    traceProvider->trace("free");
    return umfMemoryProviderFree(traceProvider->hUpstreamProvider, ptr, size);
}

static void traceGetLastError(void *provider, const char **ppMsg,
                              int32_t *pError) {
    struct umf_provider_trace_params_priv *traceProvider = (struct umf_provider_trace_params_priv *)provider;

    traceProvider->trace("get_last_native_error");
    umfMemoryProviderGetLastNativeError(traceProvider->hUpstreamProvider, ppMsg,
                                        pError);
}

static enum umf_result_t
traceGetRecommendedPageSize(void *provider, size_t size, size_t *pageSize) {
    struct umf_provider_trace_params_priv *traceProvider = (struct umf_provider_trace_params_priv *)provider;

    traceProvider->trace("get_recommended_page_size");
    return umfMemoryProviderGetRecommendedPageSize(
        traceProvider->hUpstreamProvider, size, pageSize);
}

static enum umf_result_t traceGetPageSize(void *provider, void *ptr,

                                          size_t *pageSize) {
    struct umf_provider_trace_params_priv *traceProvider = (struct umf_provider_trace_params_priv *)provider;

    traceProvider->trace("get_min_page_size");
    return umfMemoryProviderGetMinPageSize(traceProvider->hUpstreamProvider,
                                           ptr, pageSize);
}

static enum umf_result_t tracePurgeLazy(void *provider, void *ptr,
                                        size_t size) {
    struct umf_provider_trace_params_priv *traceProvider = (struct umf_provider_trace_params_priv *)provider;

    traceProvider->trace("purge_lazy");
    return umfMemoryProviderPurgeLazy(traceProvider->hUpstreamProvider, ptr,
                                      size);
}

static enum umf_result_t tracePurgeForce(void *provider, void *ptr,
                                         size_t size) {
    struct umf_provider_trace_params_priv *traceProvider = (struct umf_provider_trace_params_priv *)provider;

    traceProvider->trace("purge_force");
    return umfMemoryProviderPurgeForce(traceProvider->hUpstreamProvider, ptr,
                                       size);
}

static const char *traceName(void *provider) {
    struct umf_provider_trace_params_priv *traceProvider = (struct umf_provider_trace_params_priv *)provider;

    traceProvider->trace("name");
    return umfMemoryProviderGetName(traceProvider->hUpstreamProvider);
}

struct umf_memory_provider_ops_t UMF_TRACE_PROVIDER_OPS = {
    .version = UMF_VERSION_CURRENT,
    .initialize = traceInitialize,
    .finalize = traceFinalize,
    .alloc = traceAlloc,
    .free = traceFree,
    .get_last_native_error = traceGetLastError,
    .get_recommended_page_size = traceGetRecommendedPageSize,
    .get_min_page_size = traceGetPageSize,
    .purge_lazy = tracePurgeLazy,
    .purge_force = tracePurgeForce,
    .get_name = traceName,
};
