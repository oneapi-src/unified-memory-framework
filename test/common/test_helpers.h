// Copyright (C) 2023 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// This file contains tests for UMF pool API

#ifndef UMF_TEST_HELPERS_H
#define UMF_TEST_HELPERS_H 1

#include <umf/base.h>
#include <umf/memory_provider_ops.h>

#ifdef __cplusplus
extern "C" {
#endif

umf_memory_provider_handle_t nullProviderCreate(void);
umf_memory_provider_handle_t traceProviderCreate(
                    umf_memory_provider_handle_t hUpstreamProvider,
                    void (*trace)(const char *));

umf_memory_pool_handle_t
tracePoolCreate(umf_memory_pool_handle_t hUpstreamPool,
                umf_memory_provider_handle_t providerDesc,
                void (*trace)(const char *));

#ifdef __cplusplus
}
#endif

#endif /* UMF_TEST_HELPERS_H */
