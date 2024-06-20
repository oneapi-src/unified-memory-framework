/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <windows.h>

#include <processenv.h>
#include <processthreadsapi.h>

#include "utils_common.h"
#include "utils_concurrency.h"

#define BUFFER_SIZE 1024

static UTIL_ONCE_FLAG Page_size_is_initialized = UTIL_ONCE_FLAG_INIT;
static size_t Page_size;

static void _util_get_page_size(void) {
    SYSTEM_INFO SystemInfo;
    GetSystemInfo(&SystemInfo);
    Page_size = SystemInfo.dwPageSize;
}

size_t util_get_page_size(void) {
    util_init_once(&Page_size_is_initialized, _util_get_page_size);
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
