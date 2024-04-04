/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_MEMORY_TARGET_OPS_H
#define UMF_MEMORY_TARGET_OPS_H 1

#include <stdbool.h>

#include <umf/base.h>
#include <umf/memspace.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct umf_memory_target_t *umf_memory_target_handle_t;

typedef struct umf_memory_target_ops_t {
    /// Version of the ops structure.
    /// Should be initialized using UMF_VERSION_CURRENT
    uint32_t version;

    umf_result_t (*initialize)(void *params, void **memoryTarget);
    void (*finalize)(void *memoryTarget);

    umf_result_t (*clone)(void *memoryTarget, void **outMemoryTarget);

    umf_result_t (*pool_create_from_memspace)(
        umf_memspace_handle_t memspace, void **memoryTargets, size_t numTargets,
        umf_memspace_policy_handle_t policy, umf_memory_pool_handle_t *pool);

    umf_result_t (*memory_provider_create_from_memspace)(
        umf_memspace_handle_t memspace, void **memoryTargets, size_t numTargets,
        umf_memspace_policy_handle_t policy,
        umf_memory_provider_handle_t *provider);

    umf_result_t (*get_capacity)(void *memoryTarget, size_t *capacity);
    umf_result_t (*get_bandwidth)(void *srcMemoryTarget, void *dstMemoryTarget,
                                  size_t *bandwidth);
} umf_memory_target_ops_t;

#ifdef __cplusplus
}
#endif

#endif /* #ifndef UMF_MEMORY_TARGET_OPS_H */
