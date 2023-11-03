// Copyright (C) 2023 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <assert.h>
#include <stdlib.h>

#include <umf/memory_pool_ops.h>
#include "pool_trace.h"

struct umf_pool_trace_params_priv {
    umf_memory_pool_handle_t hUpstreamPool;
    void (*trace)(const char *);
};

struct trace_pool {
    struct umf_pool_trace_params_priv params;
};

static enum umf_result_t
traceInitialize(umf_memory_provider_handle_t provider,
                void *params, void **pool)
{
    struct trace_pool *trace_pool =
        (struct trace_pool *)malloc(sizeof(struct trace_pool));
    if (NULL == trace_pool)
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;

    struct umf_pool_trace_params *pub_params = params;
    trace_pool->params.hUpstreamPool = pub_params->hUpstreamPool;
    trace_pool->params.trace = pub_params->trace;

    (void)provider;
    assert(provider);

    *pool = trace_pool;
    return UMF_RESULT_SUCCESS;
}

static void traceFinalize(void *pool) { free(pool); }

static void *traceMalloc(void *pool, size_t size) {
    struct trace_pool *trace_pool = (struct trace_pool *)pool;

    trace_pool->params.trace("malloc");
    return umfPoolMalloc(trace_pool->params.hUpstreamPool, size);
}

static void *traceCalloc(void *pool, size_t num, size_t size) {
    struct trace_pool *trace_pool = (struct trace_pool *)pool;

    trace_pool->params.trace("calloc");
    return umfPoolCalloc(trace_pool->params.hUpstreamPool, num, size);
}

static void *traceRealloc(void *pool, void *ptr, size_t size) {
    struct trace_pool *trace_pool = (struct trace_pool *)pool;

    trace_pool->params.trace("realloc");
    return umfPoolRealloc(trace_pool->params.hUpstreamPool, ptr, size);
}

static void *traceAlignedMalloc(void *pool, size_t size, size_t alignment) {
    struct trace_pool *trace_pool = (struct trace_pool *)pool;

    trace_pool->params.trace("aligned_malloc");
    return umfPoolAlignedMalloc(trace_pool->params.hUpstreamPool, size,
                                alignment);
}

static size_t traceMallocUsableSize(void *pool, void *ptr) {
    struct trace_pool *trace_pool = (struct trace_pool *)pool;

    trace_pool->params.trace("malloc_usable_size");
    return umfPoolMallocUsableSize(trace_pool->params.hUpstreamPool, ptr);
}

static enum umf_result_t traceFree(void *pool, void *ptr) {
    struct trace_pool *trace_pool = (struct trace_pool *)pool;

    trace_pool->params.trace("free");
    return umfPoolFree(trace_pool->params.hUpstreamPool, ptr);
}

static enum umf_result_t traceGetLastStatus(void *pool) {
    struct trace_pool *trace_pool = (struct trace_pool *)pool;

    trace_pool->params.trace("get_last_native_error");
    return umfPoolGetLastAllocationError(trace_pool->params.hUpstreamPool);
}

struct umf_memory_pool_ops_t UMF_TRACE_POOL_OPS = {
    .version = UMF_VERSION_CURRENT,
    .initialize = traceInitialize,
    .finalize = traceFinalize,
    .malloc = traceMalloc,
    .realloc = traceRealloc,
    .calloc = traceCalloc,
    .aligned_malloc = traceAlignedMalloc,
    .malloc_usable_size = traceMallocUsableSize,
    .free = traceFree,
    .get_last_allocation_error = traceGetLastStatus,
};
