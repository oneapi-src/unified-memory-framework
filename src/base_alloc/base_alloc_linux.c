/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "base_alloc.h"

void *ba_os_alloc(size_t size) {
    return mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                -1, 0);
}

void ba_os_free(void *ptr, size_t size) { munmap(ptr, size); }

size_t ba_os_get_page_size(void) { return sysconf(_SC_PAGE_SIZE); }
