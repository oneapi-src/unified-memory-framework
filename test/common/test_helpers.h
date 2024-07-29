// Copyright (C) 2023-2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// This file contains helpers for tests for UMF pool API

#ifndef UMF_TEST_HELPERS_H
#define UMF_TEST_HELPERS_H 1

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <umf/base.h>
#include <umf/memory_pool.h>
#include <umf/memory_provider_ops.h>

#include "provider_trace.h"
#include "utils_common.h"

#ifdef __cplusplus
extern "C" {
#endif

// Needed for CI
#define TEST_SKIP_ERROR_CODE 125

int bufferIsFilledWithChar(void *ptr, size_t size, char c);

int buffersHaveSameContent(void *first, void *second, size_t size);

int addressIsAligned(void *ptr, size_t alignment);

umf_memory_provider_handle_t nullProviderCreate(void);

umf_memory_provider_handle_t
traceProviderCreate(umf_memory_provider_handle_t hUpstreamProvider,
                    bool own_upstream, void *trace_context,
                    trace_handler_t trace_handler);

umf_memory_pool_handle_t
tracePoolCreate(umf_memory_pool_handle_t hUpstreamPool,
                umf_memory_provider_handle_t providerDesc, void *trace_context,
                trace_handler_t trace_handler);

#ifdef __cplusplus
}
#endif

#endif /* UMF_TEST_HELPERS_H */
