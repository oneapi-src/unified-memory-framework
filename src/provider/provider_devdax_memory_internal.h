/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#ifndef UMF_DEVDAX_MEMORY_PROVIDER_INTERNAL_H
#define UMF_DEVDAX_MEMORY_PROVIDER_INTERNAL_H

#include <umf/providers/provider_os_memory.h>

#include "utils_concurrency.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct devdax_memory_provider_t {
    char path[PATH_MAX]; // a path to the device DAX
    size_t size;         // size of the file used for memory mapping
    void *base;          // base address of memory mapping
    size_t offset;       // offset in the file used for memory mapping
    os_mutex_t lock;     // lock of ptr and offset
    unsigned protection; // combination of OS-specific protection flags
} devdax_memory_provider_t;

#ifdef __cplusplus
}
#endif

#endif /* UMF_DEVDAX_MEMORY_PROVIDER_INTERNAL_H */
