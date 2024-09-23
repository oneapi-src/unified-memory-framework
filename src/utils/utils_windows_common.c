/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <windows.h>

#include <assert.h>
#include <processenv.h>
#include <processthreadsapi.h>
#include <stdio.h>
#include <string.h>
#include <sysinfoapi.h>

#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_log.h"

#define BUFFER_SIZE 1024

static UTIL_ONCE_FLAG Page_size_is_initialized = UTIL_ONCE_FLAG_INIT;
static size_t Page_size;

static void _utils_get_page_size(void) {
    SYSTEM_INFO SystemInfo;
    GetSystemInfo(&SystemInfo);
    Page_size = SystemInfo.dwPageSize;
}

size_t utils_get_page_size(void) {
    utils_init_once(&Page_size_is_initialized, _utils_get_page_size);
    return Page_size;
}

int utils_getpid(void) { return GetCurrentProcessId(); }

int utils_gettid(void) { return GetCurrentThreadId(); }

int utils_close_fd(int fd) {
    (void)fd; // unused
    return -1;
}

umf_result_t utils_duplicate_fd(int pid, int fd_in, int *fd_out) {
    (void)pid;    // unused
    (void)fd_in;  // unused
    (void)fd_out; // unused
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

umf_result_t utils_translate_mem_protection_flags(unsigned in_protection,
                                                  unsigned *out_protection) {
    switch (in_protection) {
    case UMF_PROTECTION_NONE:
        *out_protection = PAGE_NOACCESS;
        return UMF_RESULT_SUCCESS;
    case UMF_PROTECTION_EXEC:
        *out_protection = PAGE_EXECUTE;
        return UMF_RESULT_SUCCESS;
    case (UMF_PROTECTION_EXEC | UMF_PROTECTION_READ):
        *out_protection = PAGE_EXECUTE_READ;
        return UMF_RESULT_SUCCESS;
    case (UMF_PROTECTION_EXEC | UMF_PROTECTION_READ | UMF_PROTECTION_WRITE):
        *out_protection = PAGE_EXECUTE_READWRITE;
        return UMF_RESULT_SUCCESS;
    case (UMF_PROTECTION_EXEC | UMF_PROTECTION_WRITE):
        *out_protection = PAGE_EXECUTE_WRITECOPY;
        return UMF_RESULT_SUCCESS;
    case UMF_PROTECTION_READ:
        *out_protection = PAGE_READONLY;
        return UMF_RESULT_SUCCESS;
    case (UMF_PROTECTION_READ | UMF_PROTECTION_WRITE):
        *out_protection = PAGE_READWRITE;
        return UMF_RESULT_SUCCESS;
    case UMF_PROTECTION_WRITE:
        *out_protection = PAGE_WRITECOPY;
        return UMF_RESULT_SUCCESS;
    }
    LOG_ERR(
        "utils_translate_mem_protection_flags(): unsupported protection flag: "
        "%u",
        in_protection);
    return UMF_RESULT_ERROR_INVALID_ARGUMENT;
}

umf_result_t
utils_translate_mem_visibility_flag(umf_memory_visibility_t in_flag,
                                    unsigned *out_flag) {
    switch (in_flag) {
    case UMF_MEM_MAP_PRIVATE:
        *out_flag = 0; // ignored on Windows
        return UMF_RESULT_SUCCESS;
    case UMF_MEM_MAP_SHARED:
        return UMF_RESULT_ERROR_NOT_SUPPORTED; // not supported on Windows yet
    case UMF_MEM_MAP_SYNC:
        return UMF_RESULT_ERROR_NOT_SUPPORTED; // not supported on Windows yet
    }
    return UMF_RESULT_ERROR_INVALID_ARGUMENT;
}

// create a shared memory file
int utils_shm_create(const char *shm_name, size_t size) {
    (void)shm_name; // unused
    (void)size;     // unused
    return 0;       // ignored on Windows
}

// open a shared memory file
int utils_shm_open(const char *shm_name) {
    (void)shm_name; // unused
    return 0;       // ignored on Windows
}

// unlink a shared memory file
int utils_shm_unlink(const char *shm_name) {
    (void)shm_name; // unused
    return 0;       // ignored on Windows
}

int utils_create_anonymous_fd(void) {
    return 0; // ignored on Windows
}

size_t get_max_file_size(void) { return SIZE_MAX; }

int utils_get_file_size(int fd, size_t *size) {
    (void)fd;   // unused
    (void)size; // unused
    return -1;  // not supported on Windows
}

int utils_set_file_size(int fd, size_t size) {
    (void)fd;   // unused
    (void)size; // unused
    return 0;   // ignored on Windows
}

void *utils_mmap(void *hint_addr, size_t length, int prot, int flag, int fd,
                 size_t fd_offset) {
    (void)flag;      // ignored on Windows
    (void)fd;        // ignored on Windows
    (void)fd_offset; // ignored on Windows
    return VirtualAlloc(hint_addr, length, MEM_RESERVE | MEM_COMMIT, prot);
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

int utils_munmap(void *addr, size_t length) {
    // If VirtualFree() succeeds, the return value is nonzero.
    // If VirtualFree() fails, the return value is 0 (zero).
    (void)length; // unused
    return (VirtualFree(addr, 0, MEM_RELEASE) == 0);
}

int utils_purge(void *addr, size_t length, int advice) {
    // If VirtualFree() succeeds, the return value is nonzero.
    // If VirtualFree() fails, the return value is 0 (zero).
    (void)advice; // unused

    // temporarily disable the C6250 warning as we intentionally use the
    // MEM_DECOMMIT flag only
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 6250)
#endif // _MSC_VER

    return (VirtualFree(addr, length, MEM_DECOMMIT) == 0);

#if defined(_MSC_VER)
#pragma warning(pop)
#endif // _MSC_VER
}

void utils_strerror(int errnum, char *buf, size_t buflen) {
    strerror_s(buf, buflen, errnum);
}

// open a devdax
int utils_devdax_open(const char *path) {
    (void)path; // unused

    return -1;
}

// open a file
int utils_file_open(const char *path) {
    (void)path; // unused

    return -1;
}

// open a file or create
int utils_file_open_or_create(const char *path) {
    (void)path; // unused

    return -1;
}

int utils_fallocate(int fd, long offset, long len) {
    (void)fd;     // unused
    (void)offset; // unused
    (void)len;    // unused

    return -1;
}
