/*
 *
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_UTILS_NAME_H
#define UMF_UTILS_NAME_H

#include <ctype.h>
#include <string.h>

#include "utils_log.h"

#define MAX_NAME 64

static inline int utils_name_is_valid(const char *name) {
    if (!name) {
        return 0;
    }
    size_t len = strlen(name);
    if (len > MAX_NAME) {
        return 0;
    }
    for (size_t i = 0; i < len; ++i) {
        char c = name[i];
        if (!isalnum((unsigned char)c) && c != '-' && c != '_') {
            return 0;
        }
    }
    return 1;
}

static inline void utils_warn_invalid_name(const char *kind, const char *name) {
    if (!utils_name_is_valid(name)) {
        LOG_WARN("%s name \"%s\" is deprecated. It should be no more than 64 "
                 "characters including null character, containing only "
                 "alphanumerics, '_' or '-'. CTL functionality may be limited.",
                 kind, name);
    }
}

#endif /* UMF_UTILS_NAME_H */
