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

int util_env_var(const char *envvar, char *buffer, size_t buffer_size) {
    char *value = getenv(envvar);
    if (!value) {
        return 0;
    }

    size_t len = strlen(value) + 1;
    if (len > buffer_size) {
        return -len;
    }

    strncpy(buffer, value, buffer_size - 1);
    // make sure the string is NULL-terminated
    buffer[buffer_size - 1] = 0;

    return (len - 1);
}

int util_env_var_has_str(const char *envvar, const char *str) {
    char *value = getenv(envvar);
    if (value && strstr(value, str)) {
        return 1;
    }

    return 0;
}

static void _util_get_page_size(void) { Page_size = sysconf(_SC_PAGE_SIZE); }

size_t util_get_page_size(void) {
    util_init_once(&Page_size_is_initialized, _util_get_page_size);
    return Page_size;
}

char *util_strncpy(char *dest, size_t destSize, const char *src, size_t n) {
    (void)destSize; // unused
    return strncpy(dest, src, n);
}
