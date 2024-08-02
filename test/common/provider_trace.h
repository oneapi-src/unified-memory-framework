// Copyright (C) 2023-2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#ifndef UMF_TEST_TRACE_PROVIDER_H
#define UMF_TEST_TRACE_PROVIDER_H

#include <stdbool.h>

#include <umf/memory_provider.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef void (*trace_handler_t)(void *, const char *);
typedef struct umf_provider_trace_params {
    umf_memory_provider_handle_t hUpstreamProvider;
    bool own_upstream;
    void *trace_context;
    trace_handler_t trace_handler;
} umf_provider_trace_params_t;

extern umf_memory_provider_ops_t UMF_TRACE_PROVIDER_OPS;

#if defined(__cplusplus)
}
#endif

#endif // UMF_TEST_TRACE_PROVIDER_H
