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

/// @brief Protection of the memory allocations
typedef enum umf_mem_protection_flags_t {
    UMF_PROTECTION_NONE = (1 << 0),  ///< Memory allocations can not be accessed
    UMF_PROTECTION_READ = (1 << 1),  ///< Memory allocations can be read.
    UMF_PROTECTION_WRITE = (1 << 2), ///< Memory allocations can be written.
    UMF_PROTECTION_EXEC = (1 << 3),  ///< Memory allocations can be executed.

    UMF_PROTECTION_MAX // must be the last one
} umf_mem_protection_flags_t;

/// @brief Visibility of the memory allocations
typedef enum umf_mem_visibility_t {
    UMF_VISIBILITY_SHARED, ///< Updates to the memory allocated using OS provider are visible to other processes.
    /// TODO: need to expose functionality to share open the mapping in other process and explicit sync?
    UMF_VISIBILITY_PRIVATE, ///<  Updates to the memory allocated using OS provider are not visible to other processes.
} umf_mem_visibility_t;

/// @brief Memory binding mode
///
/// Specifies how memory is bound to NUMA nodes on systems that support NUMA.
/// Not every mode is supported on every system.
typedef enum umf_numa_mode_t {
    UMF_NUMA_MODE_DEFAULT, ///< Default binding mode. Actual binding policy is system-specific.
    ///  On linux this corresponds to MPOL_DEFAULT. If this mode is specified,
    ///  nodemask must be NULL and maxnode must be 0.
    UMF_NUMA_MODE_BIND, ///< Restricts memory allocation to nodes specified in nodemask. Allocations
                        ///  might come from any of the allowed nodes.
    UMF_NUMA_MODE_INTERLEAVE, ///< Interleaves memory allocations across the set of nodes specified in nodemask.
    UMF_NUMA_MODE_PREFERRED, ///< Specifies preferred node for allocation. If allocation cannot be fulfilled,
    ///  memory will be allocated from other nodes.
    UMF_NUMA_MODE_LOCAL, ///< The memory is allocated on the node of the CPU that triggered the allocation.
    ///  If this mode is specified, nodemask must be NULL and maxnode must be 0.
    /// TODO: should this be a hint or strict policy?
} umf_numa_mode_t;

/// @brief Memory provider settings struct
typedef struct umf_os_memory_provider_params_t {
    /// combination of 'umf_mem_protection_flags_t' flags
    unsigned protection;

    /// shared or private visibility of memory mapped by a provider
    umf_mem_visibility_t visibility;

    // NUMA config
    /// points to a bit mask of nodes containing up to maxnode bits, depending on
    /// selected numa_mode newly allocated memory will be bound to those nodes
    unsigned long *nodemask;
    /// max number of bits in nodemask
    unsigned long maxnode;
    /// describes how nodemask is interpreted
    umf_numa_mode_t numa_mode;

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
        0                                           /* traces */
    };

    return params;
}

#ifdef __cplusplus
}
#endif

#endif /* UMF_OS_MEMORY_PROVIDER_H */
