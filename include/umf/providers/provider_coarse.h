// Copyright (C) 2023-2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#ifndef UMF_COARSE_PROVIDER_H
#define UMF_COARSE_PROVIDER_H

#include <stdbool.h>
#include <umf/memory_provider.h>

#if defined(__cplusplus)
extern "C" {
#endif

/// @brief Coarse Memory Provider settings struct.
typedef struct coarse_memory_provider_params_t {
    /// Handle to the upstream memory provider, could be NULL.
    umf_memory_provider_handle_t upstream_memory_provider;

    /// When set, the init buffer would be pre-allocated (with
    /// `init_buffer_size` bytes) during creation time. The memory used to
    /// pre-allocate it would be taken either from the `init_buffer` or from
    /// the `upstream_memory_provider`, so either one of them has to be set.
    bool immediate_init;

    /// Init buffer used to pre-allocate memory at the creation time, could be
    /// NULL.
    void *init_buffer;

    /// Size of the pre-allocated buffer. If the `init_buffer` is set, the
    /// `init_buffer_size` should be the size of this buffer.
    size_t init_buffer_size;

    /// Enable extra tracing (TODO - move to CTL)
    bool trace;

    /// If this flag is set, the Coarse Provider wouldn't ask the upstream
    /// memory provider to free the memory during destruction.
    bool WA_do_not_free_upstream;
} coarse_memory_provider_params_t;

/// @brief Coarse Memory Provider stats (TODO move to CTL)
typedef struct coarse_memory_provider_stats_t {
    /// Total allocation size.
    size_t alloc_size;

    /// Size of used memory.
    size_t used_size;

    /// Number of memory blocks allocated from the upstream provider.
    size_t upstream_blocks_num;

    /// Total number of allocated memory blocks.
    size_t blocks_num;

    /// Number of free memory blocks.
    size_t free_blocks_num;
} coarse_memory_provider_stats_t;

umf_memory_provider_ops_t *umfCoarseMemoryProviderOps(void);

// TODO use CTL
coarse_memory_provider_stats_t
umfCoarseMemoryProviderGetStats(umf_memory_provider_handle_t provider);

umf_memory_provider_handle_t umfCoarseMemoryProviderGetUpstreamProvider(
    umf_memory_provider_handle_t provider);

#ifdef __cplusplus
}
#endif

#endif // UMF_COARSE_PROVIDER_H
