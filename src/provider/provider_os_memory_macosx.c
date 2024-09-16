/*
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <sys/mman.h>

#include <umf/providers/provider_os_memory.h>

#include "provider_os_memory_internal.h"
#include "utils_log.h"

umf_result_t os_translate_mem_visibility_flag(umf_memory_visibility_t in_flag,
                                              unsigned *out_flag) {
    switch (in_flag) {
    case UMF_MEM_MAP_PRIVATE:
        *out_flag = MAP_PRIVATE;
        return UMF_RESULT_SUCCESS;
    case UMF_MEM_MAP_SHARED:
        return UMF_RESULT_ERROR_NOT_SUPPORTED; // not supported on MacOSX
    }
    return UMF_RESULT_ERROR_INVALID_ARGUMENT;
}

// create a shared memory file
int os_shm_create(const char *shm_name, size_t size) {
    (void)shm_name; // unused
    (void)size;     // unused
    return 0;       // ignored on MacOSX
}

// open a shared memory file
int os_shm_open(const char *shm_name) {
    (void)shm_name; // unused
    return 0;       // ignored on MacOSX
}

// unlink a shared memory file
int os_shm_unlink(const char *shm_name) {
    (void)shm_name; // unused
    return 0;       // ignored on MacOSX
}

// create an anonymous file descriptor
int os_create_anonymous_fd(void) {
    return 0; // ignored on MacOSX
}

int os_get_file_size(int fd, size_t *size) {
    (void)fd;   // unused
    (void)size; // unused
    return -1;  // not supported on MacOSX
}

int os_set_file_size(int fd, size_t size) {
    (void)fd;   // unused
    (void)size; // unused
    return 0;   // ignored on MacOSX
}

void *os_devdax_mmap(void *hint_addr, size_t length, int prot, int fd) {
    (void)hint_addr; // unused
    (void)length;    // unused
    (void)prot;      // unused
    (void)fd;        // unused
    return NULL;     // not supported on Windows
}

int os_fallocate(int fd, long offset, long len) {
    (void)fd;     // unused
    (void)offset; // unused
    (void)len;    // unused

    return -1;
}
