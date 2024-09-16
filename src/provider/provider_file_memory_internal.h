/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#ifndef UMF_FILE_MEMORY_PROVIDER_INTERNAL_H
#define UMF_FILE_MEMORY_PROVIDER_INTERNAL_H

#include <umf/providers/provider_os_memory.h>

#include "critnib.h"
#include "utils_concurrency.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct file_memory_provider_t {
    os_mutex_t lock; // lock for file parameters (size and offsets)

    char path[PATH_MAX]; // a path to the file
    int fd;              // file descriptor for memory mapping
    size_t size_fd;      // size of the file used for memory mappings
    size_t offset_fd;    // offset in the file used for memory mappings

    void *base_mmap;    // base address of the current memory mapping
    size_t size_mmap;   // size of the current memory mapping
    size_t offset_mmap; // data offset in the current memory mapping

    unsigned protection; // combination of OS-specific protection flags
    unsigned visibility; // memory visibility mode
    size_t page_size;    // minimum page size

    critnib *mmaps; // a critnib map storing mmap mappings (addr, size)

    // A critnib map storing (ptr, fd_offset + 1) pairs. We add 1 to fd_offset
    // in order to be able to store fd_offset equal 0, because
    // critnib_get() returns value or NULL, so a value cannot equal 0.
    // It is needed mainly in the get_ipc_handle and open_ipc_handle hooks
    // to mmap a specific part of a file.
    critnib *fd_offset_map;
} file_memory_provider_t;

#ifdef __cplusplus
}
#endif

#endif /* UMF_FILE_MEMORY_PROVIDER_INTERNAL_H */
