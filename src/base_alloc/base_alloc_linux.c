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

// The highest possible priority (101) is used, because the constructor should be called
// as the first one and the destructor as the last one in order to avoid use-after-free.
void __attribute__((constructor(101))) umf_ba_constructor(void) {}

void __attribute__((destructor(101))) umf_ba_destructor(void) {
    umf_ba_destroy_global();
}

void *ba_os_alloc(size_t size) {
    return mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                -1, 0);
}

void ba_os_free(void *ptr, size_t size) {
    int ret = munmap(ptr, size);
    assert(ret == 0);
    (void)ret; // unused
}

size_t ba_os_get_page_size(void) { return sysconf(_SC_PAGE_SIZE); }
