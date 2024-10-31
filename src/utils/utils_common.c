/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <string.h>

#include "utils_assert.h"
#include "utils_common.h"

// align a pointer up and a size down
void utils_align_ptr_up_size_down(void **ptr, size_t *size, size_t alignment) {
    uintptr_t p = (uintptr_t)*ptr;
    size_t s = *size;

    // align the pointer up to 'alignment' bytes and adjust the size down
    size_t rest = p & (alignment - 1);
    if (rest) {
        p = ALIGN_UP(p, alignment);
        s -= alignment - rest;
    }

    ASSERT(IS_ALIGNED(p, alignment));
    ASSERT(IS_ALIGNED(s, alignment));

    *ptr = (void *)p;
    *size = s;
}

// align a pointer down and a size up (for mmap()/munmap())
void utils_align_ptr_down_size_up(void **ptr, size_t *size, size_t alignment) {
    uintptr_t p = (uintptr_t)*ptr;
    size_t s = *size;

    // align the pointer down to 'alignment' bytes and adjust the size up
    size_t rest = p & (alignment - 1);
    if (rest) {
        p = ALIGN_DOWN(p, alignment);
        s += rest;
    }

    // align the size up to 'alignment' bytes
    s = ALIGN_UP(s, alignment);

    ASSERT(IS_ALIGNED(p, alignment));
    ASSERT(IS_ALIGNED(s, alignment));

    *ptr = (void *)p;
    *size = s;
}

int utils_env_var_has_str(const char *envvar, const char *str) {
    char *value = getenv(envvar);
    if (value && strstr(value, str)) {
        return 1;
    }

    return 0;
}

// check if we are running in the proxy library
int utils_is_running_in_proxy_lib(void) {
    return utils_env_var_has_str("LD_PRELOAD", "libumf_proxy.so");
}

const char *utils_parse_var(const char *var, const char *option,
                            const char **extraArg) {
    const char *found = strstr(var, option);
    // ensure that found string is first on list or it's a separating semicolon
    if (!found) {
        return NULL;
    }
    // if found string is not at the beginning of var ensure it's preceded by ';'
    if (found != var && *(found - 1) != ';') {
        return NULL;
    }

    const char *endFound = found + strlen(option);
    if (!extraArg) {
        // if there is no argument, matched string should end with ';' or '\0'
        if (*endFound != '\0' && *endFound != ';') {
            return NULL;
        }
        return found;
    }

    // check if matched string ends with ','
    if (*endFound != ',') {
        return NULL;
    }

    *extraArg = endFound + 1;

    return found;
}

int utils_copy_path(const char *in_path, char out_path[], size_t path_max) {
    // (- 1) because there should be a room for the terminating null byte ('\0')
    size_t max_len = path_max - 1;

    if (strlen(in_path) > max_len) {
        LOG_ERR("path of the %s file is longer than %zu bytes", in_path,
                max_len);
        return -1;
    }

    strncpy(out_path, in_path, max_len);
    out_path[path_max - 1] = '\0'; // the terminating null byte

    return 0;
}

umf_result_t utils_translate_flags(unsigned in_flags, unsigned max,
                                   umf_result_t (*translate_flag)(unsigned,
                                                                  unsigned *),
                                   unsigned *out_flags) {
    unsigned out_f = 0;
    for (unsigned n = 1; n < max; n <<= 1) {
        if (in_flags & n) {
            unsigned flag;
            umf_result_t result = translate_flag(n, &flag);
            if (result != UMF_RESULT_SUCCESS) {
                return result;
            }
            out_f |= flag;
            in_flags &= ~n; // clear this bit
        }
    }

    if (in_flags != 0) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *out_flags = out_f;
    return UMF_RESULT_SUCCESS;
}
