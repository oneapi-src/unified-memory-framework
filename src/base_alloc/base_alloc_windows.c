/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <windows.h>

void *ba_os_alloc(size_t size) {
    return VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
}

void ba_os_free(void *ptr, size_t size) { VirtualFree(ptr, 0, MEM_RELEASE); }

size_t ba_os_get_page_size(void) { return 4096; /* TODO */ }

//
// TODO:
// 1) implement ba_os_get_page_size()
//
