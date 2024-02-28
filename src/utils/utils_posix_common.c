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
