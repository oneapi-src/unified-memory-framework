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

static void _util_get_page_size(void) {
    Page_size = (size_t)sysconf(_SC_PAGE_SIZE);
}

size_t util_get_page_size(void) {
    util_init_once(&Page_size_is_initialized, _util_get_page_size);
    return Page_size;
}
