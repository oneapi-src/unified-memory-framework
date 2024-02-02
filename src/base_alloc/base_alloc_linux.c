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

void *baOsAlloc(size_t size) {
    return mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                -1, 0);
}

void baOsFree(void *ptr, size_t size) {
    int ret = munmap(ptr, size);
    assert(ret == 0);
    (void)ret; // unused
}

size_t baOsGetPageSize(void) { return sysconf(_SC_PAGE_SIZE); }
