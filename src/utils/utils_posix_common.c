/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "utils_concurrency.h"

static UTIL_ONCE_FLAG Page_size_is_initialized = UTIL_ONCE_FLAG_INIT;
static size_t Page_size;

static void _util_get_page_size(void) { Page_size = sysconf(_SC_PAGE_SIZE); }

size_t util_get_page_size(void) {
    util_init_once(&Page_size_is_initialized, _util_get_page_size);
    return Page_size;
}

int utils_getpid(void) { return getpid(); }

int utils_gettid(void) {
#ifdef __APPLE__
    uint64_t tid64;
    pthread_threadid_np(NULL, &tid64);
    return (int)tid64;
#else
    // Some older OSes does not have
    // the gettid() function implemented,
    // so let's use the syscall instead:
    return syscall(SYS_gettid);
#endif
}
