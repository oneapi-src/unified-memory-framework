/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "utils_common.h"
#include "utils_assert.h"

// align a pointer and a size
void util_align_ptr_size(void **ptr, size_t *size, size_t alignment) {
    uintptr_t p = (uintptr_t)*ptr;
    size_t s = *size;

    // align pointer to 'alignment' bytes and adjust the size
    size_t rest = p & (alignment - 1);
    if (rest) {
        p += alignment - rest;
        s -= alignment - rest;
    }

    ASSERT((p & (alignment - 1)) == 0);
    ASSERT((s & (alignment - 1)) == 0);

    *ptr = (void *)p;
    *size = s;
}

// check if we are running in the proxy library
int util_is_running_in_proxy_lib(void) {
    return util_env_var_has_str("LD_PRELOAD", "libumf_proxy.so");
}
