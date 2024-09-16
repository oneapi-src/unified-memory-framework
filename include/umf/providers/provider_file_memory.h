/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#ifndef UMF_FILE_MEMORY_PROVIDER_H
#define UMF_FILE_MEMORY_PROVIDER_H

#include <umf/providers/provider_os_memory.h>

#ifdef __cplusplus
extern "C" {
#endif

/// @cond
#define UMF_FILE_RESULTS_START_FROM 3000
/// @endcond

/// @brief Memory provider settings struct
typedef struct umf_file_memory_provider_params_t {
    /// a path to the file (of maximum length PATH_MAX characters)
    const char *path;
    /// combination of 'umf_mem_protection_flags_t' flags
    unsigned protection;
    /// memory visibility mode
    umf_memory_visibility_t visibility;
} umf_file_memory_provider_params_t;

/// @brief File Memory Provider operation results
typedef enum umf_file_memory_provider_native_error {
    UMF_FILE_RESULT_SUCCESS = UMF_FILE_RESULTS_START_FROM, ///< Success
    UMF_FILE_RESULT_ERROR_ALLOC_FAILED,       ///< Memory allocation failed
    UMF_FILE_RESULT_ERROR_FREE_FAILED,        ///< Memory deallocation failed
    UMF_FILE_RESULT_ERROR_PURGE_FORCE_FAILED, ///< Force purging failed
} umf_file_memory_provider_native_error_t;

umf_memory_provider_ops_t *umfFileMemoryProviderOps(void);

/// @brief Create default params for the file memory provider
static inline umf_file_memory_provider_params_t
umfFileMemoryProviderParamsDefault(const char *path) {
    umf_file_memory_provider_params_t params = {
        path,                                       /* a path to the file */
        UMF_PROTECTION_READ | UMF_PROTECTION_WRITE, /* protection */
        UMF_MEM_MAP_PRIVATE,                        /* visibility mode */
    };

    return params;
}

#ifdef __cplusplus
}
#endif

#endif /* UMF_FILE_MEMORY_PROVIDER_H */
