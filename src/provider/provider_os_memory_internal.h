/*
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#ifndef UMF_OS_MEMORY_PROVIDER_INTERNAL_H
#define UMF_OS_MEMORY_PROVIDER_INTERNAL_H

#include <limits.h>
#include <stdbool.h>

#if defined(_WIN32) && !defined(NAME_MAX)
#include <stdlib.h>
#define NAME_MAX _MAX_FNAME
#endif /* defined(_WIN32) && !defined(NAME_MAX) */

#include <umf/providers/provider_os_memory.h>

#include "critnib.h"
#include "umf_hwloc.h"
#include "utils_common.h"
#include "utils_concurrency.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct os_memory_provider_t {
    unsigned protection; // combination of OS-specific protection flags
    unsigned visibility; // memory visibility mode

    // IPC is enabled only if (in_params->visibility == UMF_MEM_MAP_SHARED)
    bool IPC_enabled;

    // a name of a shared memory file (valid only in case of the shared memory visibility)
    char shm_name[NAME_MAX];

    int fd;                // file descriptor for memory mapping
    size_t size_fd;        // size of file used for memory mapping
    size_t max_size_fd;    // maximum size of file used for memory mapping
    utils_mutex_t lock_fd; // lock for updating file size

    // A critnib map storing (ptr, fd_offset + 1) pairs. We add 1 to fd_offset
    // in order to be able to store fd_offset equal 0, because
    // critnib_get() returns value or NULL, so a value cannot equal 0.
    // It is needed mainly in the get_ipc_handle and open_ipc_handle hooks
    // to mmap a specific part of a file.
    critnib *fd_offset_map;

    // NUMA config
    umf_numa_mode_t mode;
    hwloc_bitmap_t *nodeset;
    unsigned nodeset_len;
    char *nodeset_str_buf;
    hwloc_membind_policy_t numa_policy;
    int numa_flags; // combination of hwloc flags

    size_t part_size;
    size_t alloc_sum; // sum of all allocations - used for manual interleaving

    struct {
        unsigned weight;
        hwloc_bitmap_t target;
    } *partitions;
    unsigned partitions_len;
    size_t partitions_weight_sum;

    hwloc_topology_t topo;
} os_memory_provider_t;

#ifdef __cplusplus
}
#endif

#endif /* UMF_OS_MEMORY_PROVIDER_INTERNAL_H */
