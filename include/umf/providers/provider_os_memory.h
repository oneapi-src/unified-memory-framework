/*
 * Copyright (C) 2022-2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#ifndef UMF_OS_MEMORY_PROVIDER_H
#define UMF_OS_MEMORY_PROVIDER_H

#include "umf/memory_provider.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UMF_OS_RESULTS_START_FROM 1000

typedef enum umf_mem_protection_flags_t {
    UMF_PROTECTION_NONE = (1 << 0),
    UMF_PROTECTION_READ = (1 << 1),
    UMF_PROTECTION_WRITE = (1 << 2),
    UMF_PROTECTION_EXEC = (1 << 3),

    UMF_PROTECTION_MAX // must be the last one
} umf_mem_protection_flags_t;

typedef enum umf_mem_visibility_t {
    UMF_VISIBILITY_SHARED,
    UMF_VISIBILITY_PRIVATE,
} umf_mem_visibility_t;

typedef enum umf_numa_mode_t {
    UMF_NUMA_MODE_DEFAULT,
    UMF_NUMA_MODE_BIND,
    UMF_NUMA_MODE_INTERLEAVE,
    /* TODO: consider removing UMF_NUMA_MODE_PREFERRED and rely only on combination of BIND mode and STRICT flag like hwloc */
    UMF_NUMA_MODE_PREFERRED,
    UMF_NUMA_MODE_LOCAL,
    UMF_NUMA_MODE_STATIC_NODES,
    UMF_NUMA_MODE_RELATIVE_NODES,
} umf_numa_mode_t;

typedef enum umf_numa_flags_t {
    UMF_NUMA_FLAGS_STRICT = (1 << 0),
    UMF_NUMA_FLAGS_MOVE = (1 << 1),
    UMF_NUMA_FLAGS_MOVE_ALL = (1 << 2),

    UMF_NUMA_FLAGS_MAX // must be the last one
} umf_numa_flags_t;

typedef enum umf_purge_advise_t {
    UMF_PURGE_LAZY,
    UMF_PURGE_FORCE,
} umf_purge_advise_t;

/// @brief Memory provider settings struct
typedef struct umf_os_memory_provider_params_t {
    /// combination of 'umf_mem_protection_flags_t' flags
    unsigned protection;
    /// shared or private visibility of memory mapped by a provider
    /// sets MAP_SHARED and MAP_PRIVATE flags respectively on internal mmap() calls
    umf_mem_visibility_t visibility;

    // NUMA config
    /// nodemask used in internal mbind() calls
    unsigned long *nodemask;
    /// maximum number of nodes in \p nodemask
    unsigned long maxnode;
    /// flag that relates to one of the MPOL_* flags used in internal mbind() calls
    umf_numa_mode_t numa_mode;
    /// combination of 'umf_numa_flags_t' flags
    unsigned numa_flags;

    // others
    /// log level of debug traces
    int traces;
} umf_os_memory_provider_params_t;

typedef enum umf_os_memory_provider_native_error {
    UMF_OS_RESULT_SUCCESS = UMF_OS_RESULTS_START_FROM,
    UMF_OS_RESULT_ERROR_ALLOC_FAILED,
    UMF_OS_RESULT_ERROR_ADDRESS_NOT_ALIGNED,
    UMF_OS_RESULT_ERROR_BIND_FAILED,
    UMF_OS_RESULT_ERROR_FREE_FAILED,
    UMF_OS_RESULT_ERROR_PURGE_LAZY_FAILED,
    UMF_OS_RESULT_ERROR_PURGE_FORCE_FAILED,
    UMF_OS_RESULT_ERROR_TOPO_DISCOVERY_FAILED,
} umf_os_memory_provider_native_error_t;

umf_memory_provider_ops_t *umfOsMemoryProviderOps(void);

/// @brief Create default params for os memory provider
static inline umf_os_memory_provider_params_t
umfOsMemoryProviderParamsDefault(void) {
    umf_os_memory_provider_params_t params = {
        UMF_PROTECTION_READ | UMF_PROTECTION_WRITE, /* protection */
        UMF_VISIBILITY_PRIVATE,                     /* visibility */
        NULL,                                       /* nodemask */
        0,                                          /* maxnode */
        UMF_NUMA_MODE_DEFAULT,                      /* numa_mode */
        0,                                          /* numa_flags */
        0                                           /* traces */
    };

    return params;
}

#ifdef __cplusplus
}
#endif

#endif /* UMF_OS_MEMORY_PROVIDER_H */
