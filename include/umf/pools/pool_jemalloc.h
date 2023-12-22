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

#include <stdbool.h>

#include <umf/memory_pool_ops.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Configuration of Jemalloc pool
typedef struct umf_jemalloc_pool_params_t {
    /// Use memory provider for metadata allocations when true
    bool metadata_use_provider;
} umf_jemalloc_pool_params_t;

extern umf_memory_pool_ops_t UMF_JEMALLOC_POOL_OPS;

#ifdef __cplusplus
}
#endif

#endif /* UMF_JEMALLOC_MEMORY_POOL_H */
