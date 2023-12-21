/*
 *
 * Copyright (C) 2023 Intel Corporation
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

typedef struct umf_memory_pool_t {
    void *pool_priv;
    umf_memory_pool_ops_t ops;

    // Memory provider used by the pool.
    umf_memory_provider_handle_t provider;
    // Tells whether memory provider is owned by the pool.
    bool own_provider;
} umf_memory_pool_t;

UMF_EXPORT umf_result_t
umfPoolCreateEx(const umf_memory_pool_ops_t *pool_ops, void *pool_params,
                const umf_memory_provider_ops_t *provider_ops,
                void *provider_params, umf_memory_pool_handle_t *hPool);

#ifdef __cplusplus
}
#endif

#endif /* UMF_MEMORY_POOL_INTERNAL_H */
