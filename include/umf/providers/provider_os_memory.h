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

enum umf_mem_protection_flags {
    UMF_PROTECTION_NONE = (1 << 0),
    UMF_PROTECTION_READ = (1 << 1),
    UMF_PROTECTION_WRITE = (1 << 2),
    UMF_PROTECTION_EXEC = (1 << 3),

    UMF_PROTECTION_MAX // must be the last one
};

enum umf_mem_visibility {
    UMF_VISIBILITY_SHARED,
    UMF_VISIBILITY_PRIVATE,
};

enum umf_numa_mode {
    UMF_NUMA_MODE_DEFAULT,
    UMF_NUMA_MODE_BIND,
    UMF_NUMA_MODE_INTERLEAVE,
    UMF_NUMA_MODE_PREFERRED,
    UMF_NUMA_MODE_LOCAL,
    UMF_NUMA_MODE_STATIC_NODES,
    UMF_NUMA_MODE_RELATIVE_NODES,
};

enum umf_numa_flags {
    UMF_NUMA_FLAGS_STRICT = (1 << 0),
    UMF_NUMA_FLAGS_MOVE = (1 << 1),
    UMF_NUMA_FLAGS_MOVE_ALL = (1 << 2),

    UMF_NUMA_FLAGS_MAX // must be the last one
};

enum umf_purge_advise {
    UMF_PURGE_LAZY,
    UMF_PURGE_FORCE,
};

typedef struct umf_os_memory_provider_params_s {
    unsigned protection; // combination of 'enum umf_mem_protection_flags' flags
    enum umf_mem_visibility visibility;

    // NUMA config
    unsigned long *nodemask;
    unsigned long maxnode;
    enum umf_numa_mode numa_mode;
    unsigned numa_flags; // combination of 'enum umf_numa_flags' flags

    // others
    int traces; // log level of debug traces
} umf_os_memory_provider_params_t;

enum umf_os_memory_provider_native_error {
    UMF_OS_RESULT_SUCCESS = UMF_OS_RESULTS_START_FROM,
    UMF_OS_RESULT_ERROR_WRONG_ALIGNMENT,
    UMF_OS_RESULT_ERROR_ALLOC_FAILED,
    UMF_OS_RESULT_ERROR_ADDRESS_NOT_ALIGNED,
    UMF_OS_RESULT_ERROR_BIND_FAILED,
    UMF_OS_RESULT_ERROR_FREE_FAILED,
    UMF_OS_RESULT_ERROR_PURGE_LAZY_FAILED,
    UMF_OS_RESULT_ERROR_PURGE_FORCE_FAILED,
};

extern struct umf_memory_provider_ops_t UMF_OS_MEMORY_PROVIDER_OPS;

#ifdef __cplusplus
}
#endif

#endif /* UMF_OS_MEMORY_PROVIDER_H */
