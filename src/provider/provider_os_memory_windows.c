/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <windows.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sysinfoapi.h>

#include <umf/providers/provider_os_memory.h>

#include "utils_concurrency.h"
#include "utils_log.h"

static UTIL_ONCE_FLAG Page_size_is_initialized = UTIL_ONCE_FLAG_INIT;
static size_t Page_size;

umf_result_t os_translate_mem_protection_flags(unsigned in_protection,
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
    LOG_ERR("os_translate_mem_protection_flags(): unsupported protection flag: "
            "%u",
            in_protection);
    return UMF_RESULT_ERROR_INVALID_ARGUMENT;
}

umf_result_t os_translate_mem_visibility_flag(umf_memory_visibility_t in_flag,
                                              unsigned *out_flag) {
    switch (in_flag) {
    case UMF_MEM_MAP_PRIVATE:
        *out_flag = 0; // ignored on Windows
        return UMF_RESULT_SUCCESS;
    case UMF_MEM_MAP_SHARED:
        return UMF_RESULT_ERROR_NOT_SUPPORTED; // not supported on Windows yet
    }
    return UMF_RESULT_ERROR_INVALID_ARGUMENT;
}

int os_create_anonymous_fd(unsigned translated_memory_flag) {
    (void)translated_memory_flag; // unused
    return 0;                     // ignored on Windows
}

size_t get_max_file_size(void) { return SIZE_MAX; }

int os_set_file_size(int fd, size_t size) {
    (void)fd;   // unused
    (void)size; // unused
    return 0;   // ignored on Windows
}

void *os_mmap(void *hint_addr, size_t length, int prot, int flag, int fd,
              size_t fd_offset) {
    (void)flag;      // ignored on Windows
    (void)fd;        // ignored on Windows
    (void)fd_offset; // ignored on Windows
    return VirtualAlloc(hint_addr, length, MEM_RESERVE | MEM_COMMIT, prot);
}

int os_munmap(void *addr, size_t length) {
    // If VirtualFree() succeeds, the return value is nonzero.
    // If VirtualFree() fails, the return value is 0 (zero).
    (void)length; // unused
    return (VirtualFree(addr, 0, MEM_RELEASE) == 0);
}

int os_purge(void *addr, size_t length, int advice) {
    // If VirtualFree() succeeds, the return value is nonzero.
    // If VirtualFree() fails, the return value is 0 (zero).
    (void)advice; // unused
    return (VirtualFree(addr, length, MEM_DECOMMIT) == 0);
}

static void _os_get_page_size(void) {
    SYSTEM_INFO SystemInfo;
    GetSystemInfo(&SystemInfo);
    Page_size = SystemInfo.dwPageSize;
}

size_t os_get_page_size(void) {
    util_init_once(&Page_size_is_initialized, _os_get_page_size);
    return Page_size;
}

void os_strerror(int errnum, char *buf, size_t buflen) {
    strerror_s(buf, buflen, errnum);
}

int os_getpid(void) { return GetCurrentProcessId(); }

umf_result_t os_duplicate_fd(int pid, int fd_in, int *fd_out) {
    (void)pid;                             // unused
    (void)fd_in;                           // unused
    (void)fd_out;                          // unused
    return UMF_RESULT_ERROR_NOT_SUPPORTED; // unsupported
}

umf_result_t os_close_fd(int fd) {
    (void)fd;                              // unused
    return UMF_RESULT_ERROR_NOT_SUPPORTED; // unsupported
}
