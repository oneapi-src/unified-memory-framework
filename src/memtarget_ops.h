/*
 *
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_MEMTARGET_OPS_H
#define UMF_MEMTARGET_OPS_H 1

#include <umf/base.h>
#include <umf/memspace.h>
#include <umf/memtarget.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct umf_memtarget_ops_t {
    /// Version of the ops structure.
    /// Should be initialized using UMF_VERSION_CURRENT
    uint32_t version;

    umf_result_t (*initialize)(void *params, void **memoryTarget);
    void (*finalize)(void *memoryTarget);

    umf_result_t (*clone)(void *memoryTarget, void **outMemoryTarget);

    umf_result_t (*pool_create_from_memspace)(
        umf_const_memspace_handle_t memspace, void **memoryTargets,
        size_t numTargets, umf_const_mempolicy_handle_t policy,
        umf_memory_pool_handle_t *pool);

    umf_result_t (*memory_provider_create_from_memspace)(
        umf_const_memspace_handle_t memspace, void **memoryTargets,
        size_t numTargets, umf_const_mempolicy_handle_t policy,
        umf_memory_provider_handle_t *provider);

    umf_result_t (*get_capacity)(void *memoryTarget, size_t *capacity);
    umf_result_t (*get_bandwidth)(void *srcMemoryTarget, void *dstMemoryTarget,
                                  size_t *bandwidth);
    umf_result_t (*get_latency)(void *srcMemoryTarget, void *dstMemoryTarget,
                                size_t *latency);

    umf_result_t (*get_type)(void *memoryTarget, umf_memtarget_type_t *type);
    umf_result_t (*get_id)(void *memoryTarget, unsigned *type);
    umf_result_t (*compare)(void *memTarget, void *otherMemTarget, int *result);

} umf_memtarget_ops_t;

#ifdef __cplusplus
}
#endif

#endif /* #ifndef UMF_MEMTARGET_OPS_H */
