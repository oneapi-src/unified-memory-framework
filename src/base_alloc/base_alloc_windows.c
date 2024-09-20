/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <windows.h>

#include "utils_concurrency.h"

static UTIL_ONCE_FLAG Page_size_is_initialized = UTIL_ONCE_FLAG_INIT;
static size_t Page_size;

void *ba_os_alloc(size_t size) {
    return VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
}

void ba_os_free(void *ptr, size_t size) {
    (void)size; // unused
    VirtualFree(ptr, 0, MEM_RELEASE);
}

static void _ba_os_init_page_size(void) {
    SYSTEM_INFO SystemInfo;
    GetSystemInfo(&SystemInfo);
    Page_size = SystemInfo.dwPageSize;
}

size_t ba_os_get_page_size(void) {
    utils_init_once(&Page_size_is_initialized, _ba_os_init_page_size);
    return Page_size;
}
