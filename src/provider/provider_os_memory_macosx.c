/*
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <sys/mman.h>

#include <umf/providers/provider_os_memory.h>

#include "provider_os_memory_internal.h"
#include "utils_log.h"

umf_result_t os_translate_mem_visibility_flag(umf_memory_visibility_t in_flag,
                                              unsigned *out_flag) {
    switch (in_flag) {
    case UMF_MEM_MAP_PRIVATE:
        *out_flag = MAP_PRIVATE;
        return UMF_RESULT_SUCCESS;
    case UMF_MEM_MAP_SHARED:
        return UMF_RESULT_ERROR_NOT_SUPPORTED; // not supported on MacOSX
    }
    return UMF_RESULT_ERROR_INVALID_ARGUMENT;
}

// create an anonymous file descriptor
int os_create_anonymous_fd(unsigned translated_memory_flag) {
    (void)translated_memory_flag; // unused
    return 0;                     // ignored on MacOSX
}

int os_set_file_size(int fd, size_t size) {
    (void)fd;   // unused
    (void)size; // unused
    return 0;   // ignored on MacOSX
}
