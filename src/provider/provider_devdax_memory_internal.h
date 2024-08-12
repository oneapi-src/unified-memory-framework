/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#ifndef UMF_DEVDAX_MEMORY_PROVIDER_INTERNAL_H
#define UMF_DEVDAX_MEMORY_PROVIDER_INTERNAL_H

#include <umf/providers/provider_os_memory.h>

#include "critnib.h"
#include "utils_concurrency.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NAME_MAX 255

typedef struct devdax_memory_provider_t {
    char path[NAME_MAX]; // a path to the devdax
    size_t size;         // size of the file used for memory mapping
    int fd;              // file descriptor for memory mapping
    void *base;          // base address of memory mapping
    size_t offset;       // offset in the file used for memory mapping
    os_mutex_t lock;     // lock of ptr and offset

    unsigned protection; // combination of OS-specific protection flags
    unsigned visibility; // memory visibility mode

    // A critnib map storing (ptr, fd_offset + 1) pairs. We add 1 to fd_offset
    // in order to be able to store fd_offset equal 0, because
    // critnib_get() returns value or NULL, so a value cannot equal 0.
    // It is needed mainly in the get_ipc_handle and open_ipc_handle hooks
    // to mmap a specific part of a file.
    critnib *fd_offset_map;
} devdax_memory_provider_t;

#ifdef __cplusplus
}
#endif

#endif /* UMF_DEVDAX_MEMORY_PROVIDER_INTERNAL_H */
