/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_JEMALLOC_MEMORY_POOL_H
#define UMF_JEMALLOC_MEMORY_POOL_H 1

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <umf/memory_pool_ops.h>

/// @brief Configuration of Jemalloc Pool
typedef struct umf_jemalloc_pool_params_t {
    /// Set to true if umfMemoryProviderFree() should never be called.
    bool disable_provider_free;
} umf_jemalloc_pool_params_t;

umf_memory_pool_ops_t *umfJemallocPoolOps(void);

#ifdef __cplusplus
}
#endif

#endif /* UMF_JEMALLOC_MEMORY_POOL_H */
