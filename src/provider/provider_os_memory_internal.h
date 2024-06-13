/*
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#ifndef UMF_OS_MEMORY_PROVIDER_INTERNAL_H
#define UMF_OS_MEMORY_PROVIDER_INTERNAL_H

#include <hwloc.h>
#include <umf/providers/provider_os_memory.h>

#include "critnib.h"
#include "utils_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum umf_purge_advise_t {
    UMF_PURGE_LAZY,
    UMF_PURGE_FORCE,
} umf_purge_advise_t;

#define NAME_MAX 255

typedef struct os_memory_provider_t {
    unsigned protection; // combination of OS-specific protection flags
    unsigned visibility; // memory visibility mode
    // a name of a shared memory file (valid only in case of the shared memory visibility)
    char shm_name[NAME_MAX];
    int fd;             // file descriptor for memory mapping
    size_t size_fd;     // size of file used for memory mapping
    size_t max_size_fd; // maximum size of file used for memory mapping
    // A critnib map storing (ptr, fd_offset + 1) pairs. We add 1 to fd_offset
    // in order to be able to store fd_offset equal 0, because
    // critnib_get() returns value or NULL, so a value cannot equal 0.
    // It is needed mainly in the get_ipc_handle and open_ipc_handle hooks
    // to mmap a specific part of a file.
    critnib *fd_offset_map;

    // NUMA config
    hwloc_bitmap_t *nodeset;
    unsigned nodeset_len;
    char *nodeset_str_buf;
    hwloc_membind_policy_t numa_policy;
    int numa_flags; // combination of hwloc flags

    size_t part_size;
    size_t alloc_sum; // sum of all allocations - used for manual interleaving
    hwloc_topology_t topo;
} os_memory_provider_t;

umf_result_t os_translate_flags(unsigned in_flags, unsigned max,
                                umf_result_t (*translate_flag)(unsigned,
                                                               unsigned *),
                                unsigned *out_flags);

umf_result_t os_translate_mem_protection_flags(unsigned in_protection,
                                               unsigned *out_protection);

umf_result_t os_translate_mem_visibility_flag(umf_memory_visibility_t in_flag,
                                              unsigned *out_flag);

int os_create_anonymous_fd(void);

int os_shm_create(const char *shm_name, size_t size);

int os_shm_open(const char *shm_name);

int os_shm_unlink(const char *shm_name);

size_t get_max_file_size(void);

int os_get_file_size(int fd, size_t *size);

int os_set_file_size(int fd, size_t size);

void *os_mmap(void *hint_addr, size_t length, int prot, int flag, int fd,
              size_t fd_offset);

int os_munmap(void *addr, size_t length);

int os_purge(void *addr, size_t length, int advice);

size_t os_get_page_size(void);

void os_strerror(int errnum, char *buf, size_t buflen);

umf_result_t os_duplicate_fd(int pid, int fd_in, int *fd_out);

umf_result_t os_close_fd(int fd);

#ifdef __cplusplus
}
#endif

#endif /* UMF_OS_MEMORY_PROVIDER_INTERNAL_H */
