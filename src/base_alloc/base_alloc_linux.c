/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <assert.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "base_alloc.h"
#include "base_alloc_global.h"
#include "utils_concurrency.h"

static UTIL_ONCE_FLAG Page_size_is_initialized = UTIL_ONCE_FLAG_INIT;
static size_t Page_size;

void *ba_os_alloc(size_t size) {
    return mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                -1, 0);
}

void ba_os_free(void *ptr, size_t size) {
    int ret = munmap(ptr, size);
    assert(ret == 0);
    (void)ret; // unused
}

static void _ba_os_init_page_size(void) { Page_size = sysconf(_SC_PAGE_SIZE); }

size_t ba_os_get_page_size(void) {
    util_init_once(&Page_size_is_initialized, _ba_os_init_page_size);
    return Page_size;
}
