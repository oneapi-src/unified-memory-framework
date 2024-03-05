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

static UTIL_ONCE_FLAG Page_size_is_initialized = UTIL_ONCE_FLAG_INIT;
static size_t Page_size;

int os_translate_mem_protection_flags(unsigned protection) {
    switch (protection) {
    case UMF_PROTECTION_NONE:
        return PAGE_NOACCESS;
    case UMF_PROTECTION_EXEC:
        return PAGE_EXECUTE;
    case (UMF_PROTECTION_EXEC | UMF_PROTECTION_READ):
        return PAGE_EXECUTE_READ;
    case (UMF_PROTECTION_EXEC | UMF_PROTECTION_READ | UMF_PROTECTION_WRITE):
        return PAGE_EXECUTE_READWRITE;
    case (UMF_PROTECTION_EXEC | UMF_PROTECTION_WRITE):
        return PAGE_EXECUTE_WRITECOPY;
    case UMF_PROTECTION_READ:
        return PAGE_READONLY;
    case (UMF_PROTECTION_READ | UMF_PROTECTION_WRITE):
        return PAGE_READWRITE;
    case UMF_PROTECTION_WRITE:
        return PAGE_WRITECOPY;
    }
    fprintf(stderr,
            "os_translate_mem_protection_flags(): unsupported protection flag: "
            "%u\n",
            protection);
    assert(0);
    return -1;
}

void *os_mmap(void *hint_addr, size_t length, int prot) {
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
