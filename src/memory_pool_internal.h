/*
 *
 * Copyright (C) 2023-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_MEMORY_POOL_INTERNAL_H
#define UMF_MEMORY_POOL_INTERNAL_H 1

#include <umf/base.h>
#include <umf/memory_pool.h>
#include <umf/memory_pool_ops.h>
#include <umf/memory_provider.h>

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "base_alloc.h"
#include "utils_concurrency.h"

typedef struct umf_memory_pool_t {
    void *pool_priv;
    umf_memory_pool_ops_t ops;
    umf_pool_create_flags_t flags;

    // Memory provider used by the pool.
    umf_memory_provider_handle_t provider;

    utils_mutex_t lock;
    void *tag;
} umf_memory_pool_t;

#ifdef __cplusplus
}
#endif

#endif /* UMF_MEMORY_POOL_INTERNAL_H */
