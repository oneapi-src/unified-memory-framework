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

#define BUFFER_SIZE 1024

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
