// Copyright (C) 2023 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#ifndef UMF_FIXED_PROVIDER_H
#define UMF_FIXED_PROVIDER_H

#include <umf/memory_provider.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct fixed_memory_provider_params_t {
    umf_memory_provider_handle_t upstream_memory_provider;
    size_t init_buffer_size;
    bool immediate_init; // pre-allocate soft limit
    bool trace;
} fixed_memory_provider_params_t;

typedef struct fixed_memory_provider_stats_t {
    size_t alloc_size;
    size_t used_size;
    size_t blocks_num;
} fixed_memory_provider_stats_t;

extern struct umf_memory_provider_ops_t UMF_FIXED_MEMORY_PROVIDER_OPS;

fixed_memory_provider_stats_t
umfFixedMemoryProviderGetStats(void *provider_priv);

#ifdef __cplusplus
}
#endif

#endif // UMF_FIXED_PROVIDER_H
