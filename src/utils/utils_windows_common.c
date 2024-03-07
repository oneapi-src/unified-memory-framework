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

#include "utils_concurrency.h"

#define BUFFER_SIZE 1024

static UTIL_ONCE_FLAG Page_size_is_initialized = UTIL_ONCE_FLAG_INIT;
static size_t Page_size;

int util_env_var(const char *envvar, char *buffer, size_t buffer_size) {
    int ret = GetEnvironmentVariableA(envvar, buffer, (DWORD)buffer_size);
    if (ret >= buffer_size) {
        return -ret;
    }

    return ret;
}

int util_env_var_has_str(const char *envvar, const char *str) {
    char buffer[BUFFER_SIZE];
    if (util_env_var(envvar, buffer, BUFFER_SIZE) > 0) {
        return (strstr(buffer, str) != NULL);
    }

    return 0;
}

static void _util_get_page_size(void) {
    SYSTEM_INFO SystemInfo;
    GetSystemInfo(&SystemInfo);
    Page_size = SystemInfo.dwPageSize;
}

size_t util_get_page_size(void) {
    util_init_once(&Page_size_is_initialized, _util_get_page_size);
    return Page_size;
}

char *util_strncpy(char *dest, size_t destSize, const char *src, size_t n) {
    if (strncpy_s(dest, destSize, src, n)) {
        return NULL;
    }

    return dest;
}
