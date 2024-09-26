/*
 *
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <sys/mman.h>

#include <umf/base.h>
#include <umf/memory_provider.h>

#include "utils_log.h"

umf_result_t
utils_translate_mem_visibility_flag(umf_memory_visibility_t in_flag,
                                    unsigned *out_flag) {
    switch (in_flag) {
    case UMF_MEM_MAP_PRIVATE:
        *out_flag = MAP_PRIVATE;
        return UMF_RESULT_SUCCESS;
    case UMF_MEM_MAP_SHARED:
        return UMF_RESULT_ERROR_NOT_SUPPORTED; // not supported on MacOSX
    case UMF_MEM_MAP_SYNC:
        return UMF_RESULT_ERROR_NOT_SUPPORTED; // not supported on MacOSX
    }
    return UMF_RESULT_ERROR_INVALID_ARGUMENT;
}

void *utils_mmap_file(void *hint_addr, size_t length, int prot, int flags,
                      int fd, size_t fd_offset) {
    (void)hint_addr; // unused
    (void)length;    // unused
    (void)prot;      // unused
    (void)flags;     // unused
    (void)fd;        // unused
    (void)fd_offset; // unused
    return NULL;     // not supported
}

int utils_get_file_size(int fd, size_t *size) {
    (void)fd;   // unused
    (void)size; // unused
    return -1;  // not supported on MacOSX
}

int utils_set_file_size(int fd, size_t size) {
    (void)fd;   // unused
    (void)size; // unused
    return 0;   // ignored on MacOSX
}

int utils_fallocate(int fd, long offset, long len) {
    (void)fd;     // unused
    (void)offset; // unused
    (void)len;    // unused

    return -1;
}

// create a shared memory file
int utils_shm_create(const char *shm_name, size_t size) {
    (void)shm_name; // unused
    (void)size;     // unused
    return 0;       // ignored on MacOSX
}

// open a shared memory file
int utils_shm_open(const char *shm_name) {
    (void)shm_name; // unused
    return 0;       // ignored on MacOSX
}

// unlink a shared memory file
int utils_shm_unlink(const char *shm_name) {
    (void)shm_name; // unused
    return 0;       // ignored on MacOSX
}

// create an anonymous file descriptor
int utils_create_anonymous_fd(void) {
    return 0; // ignored on MacOSX
}
