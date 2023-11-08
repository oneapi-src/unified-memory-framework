// Copyright (C) 2023 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <umf/memory_pool.h>
#include <umf/memory_provider.h>

#define UMF_DISJOINT_POOL_MIN_BUCKET_DEFAULT_SIZE ((size_t)8)

struct umf_disjoint_pool_params {
    // Minimum allocation size that will be requested from the system.
    // By default this is the minimum allocation size of each memory type.
    size_t SlabMinSize;

    // Allocations up to this limit will be subject to chunking/pooling
    size_t MaxPoolableSize;

    // When pooling, each bucket will hold a max of 'Capacity' unfreed slabs
    size_t Capacity;

    // Holds the minimum bucket size valid for allocation of a memory type.
    // This value must be a power of 2.
    size_t MinBucketSize;

    // Holds size of the pool managed by the allocator.
    size_t CurPoolSize;

    // Whether to print pool usage statistics
    int PoolTrace;
};

extern struct umf_memory_pool_ops_t UMF_DISJOINT_POOL_OPS;

static inline struct umf_disjoint_pool_params umfDisjointPoolParamsDefault() {
    struct umf_disjoint_pool_params params = {
        0,                                         /* SlabMinSize */
        0,                                         /* MaxPoolableSize */
        0,                                         /* Capacity */
        UMF_DISJOINT_POOL_MIN_BUCKET_DEFAULT_SIZE, /* MinBucketSize */
        0,                                         /* CurPoolSize */
        0                                          /* PoolTrace */
    };

    return params;
}

#ifdef __cplusplus
}
#endif
