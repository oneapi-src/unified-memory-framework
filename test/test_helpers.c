// Copyright (C) 2023 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// This file contains tests for UMF pool API

#include <assert.h>

#include "umf/memory_provider.h"
#include "pool/pool_null.h"
#include "pool/pool_trace.h"
#include "provider/provider_null.h"
#include "provider/provider_trace.h"

umf_memory_provider_handle_t nullProviderCreate(void) {
    umf_memory_provider_handle_t hProvider;
    enum umf_result_t ret = umfMemoryProviderCreate(&UMF_NULL_PROVIDER_OPS, NULL, &hProvider);

    (void)ret; /* silence unused variable warning */
    assert(ret == UMF_RESULT_SUCCESS);
    return hProvider;
}

umf_memory_provider_handle_t
traceProviderCreate(umf_memory_provider_handle_t hUpstreamProvider,
                    void (*trace)(const char *)) {
    struct umf_provider_trace_params params = {.hUpstreamProvider = hUpstreamProvider,
                                 .trace = trace};

    umf_memory_provider_handle_t hProvider;
    enum umf_result_t ret = umfMemoryProviderCreate(&UMF_TRACE_PROVIDER_OPS, &params, &hProvider);

    (void)ret; /* silence unused variable warning */
    assert(ret == UMF_RESULT_SUCCESS);
    return hProvider;
}

umf_memory_pool_handle_t
tracePoolCreate(umf_memory_pool_handle_t hUpstreamPool,
                umf_memory_provider_handle_t providerDesc,
                void (*trace)(const char *)) {
    struct umf_pool_trace_params params = {.hUpstreamPool = hUpstreamPool,
                                 .trace = trace};

    umf_memory_pool_handle_t hPool;
    enum umf_result_t ret =
        umfPoolCreate(&UMF_TRACE_POOL_OPS, &providerDesc, 1, &params, &hPool);

    (void)ret; /* silence unused variable warning */
    assert(ret == UMF_RESULT_SUCCESS);
    return hPool;
}
