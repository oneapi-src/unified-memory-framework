// Copyright (C) 2023-2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// This file contains tests for UMF pool API

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pool_null.h"
#include "pool_trace.h"
#include "provider_null.h"
#include "umf/memory_pool.h"
#include "umf/memory_provider.h"

#include "test_helpers.h"

// Check if the memory is filled with the given character
int bufferIsFilledWithChar(void *ptr, size_t size, char c) {
    char *mem = (char *)ptr;
    return (*mem == c) && memcmp(mem, mem + 1, size - 1) == 0;
}

// Check if two memory regions has the same content
int buffersHaveSameContent(void *first, void *second, size_t size) {
    return memcmp(first, second, size) == 0;
}

int addressIsAligned(void *ptr, size_t alignment) {
    return ((uintptr_t)ptr & (alignment - 1)) == 0;
}

umf_memory_provider_handle_t nullProviderCreate(void) {
    umf_memory_provider_handle_t hProvider;
    umf_result_t ret =
        umfMemoryProviderCreate(&UMF_NULL_PROVIDER_OPS, NULL, &hProvider);

    (void)ret; /* silence unused variable warning */
    assert(ret == UMF_RESULT_SUCCESS);
    return hProvider;
}

umf_memory_provider_handle_t
traceProviderCreate(umf_memory_provider_handle_t hUpstreamProvider,
                    bool own_upstream, void *trace_context,
                    trace_handler_t trace_handler) {
    umf_provider_trace_params_t params = {.hUpstreamProvider =
                                              hUpstreamProvider,
                                          .own_upstream = own_upstream,
                                          .trace_context = trace_context,
                                          .trace_handler = trace_handler};

    umf_memory_provider_handle_t hProvider;
    umf_result_t ret =
        umfMemoryProviderCreate(&UMF_TRACE_PROVIDER_OPS, &params, &hProvider);

    (void)ret; /* silence unused variable warning */
    assert(ret == UMF_RESULT_SUCCESS);
    return hProvider;
}

umf_memory_pool_handle_t
tracePoolCreate(umf_memory_pool_handle_t hUpstreamPool,
                umf_memory_provider_handle_t providerDesc, void *trace_context,
                trace_handler_t trace_handler) {
    umf_pool_trace_params_t params = {.hUpstreamPool = hUpstreamPool,
                                      .trace_context = trace_context,
                                      .trace_handler = trace_handler};

    umf_memory_pool_handle_t hPool;
    umf_result_t ret =
        umfPoolCreate(&UMF_TRACE_POOL_OPS, providerDesc, &params, 0, &hPool);

    (void)ret; /* silence unused variable warning */
    assert(ret == UMF_RESULT_SUCCESS);
    return hPool;
}
