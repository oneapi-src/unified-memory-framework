// Copyright (C) 2023 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#ifndef UMF_COARSE_PROVIDER_H
#define UMF_COARSE_PROVIDER_H

#include <stdbool.h>
#include <umf/memory_provider.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct coarse_memory_provider_params_t {
    umf_memory_provider_handle_t upstream_memory_provider;
    size_t init_buffer_size;
    bool immediate_init; // pre-allocate soft limit
    bool trace;
} coarse_memory_provider_params_t;

typedef struct coarse_memory_provider_stats_t {
    size_t alloc_size;
    size_t used_size;
    size_t upstream_blocks_num;
    size_t blocks_num;
    size_t free_blocks_num;
} coarse_memory_provider_stats_t;

extern struct umf_memory_provider_ops_t UMF_COARSE_MEMORY_PROVIDER_OPS;

coarse_memory_provider_stats_t
umfCoarseMemoryProviderGetStats(umf_memory_provider_handle_t provider);

umf_memory_provider_handle_t umfCoarseMemoryProviderGetUpstreamProvider(
    umf_memory_provider_handle_t provider);

#ifdef __cplusplus
}
#endif

#endif // UMF_coarse_PROVIDER_H
