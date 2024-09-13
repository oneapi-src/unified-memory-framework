/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#ifndef UMF_DEVDAX_MEMORY_PROVIDER_H
#define UMF_DEVDAX_MEMORY_PROVIDER_H

#include <umf/providers/provider_os_memory.h>

#ifdef __cplusplus
extern "C" {
#endif

/// @cond
#define UMF_DEVDAX_RESULTS_START_FROM 2000
/// @endcond

/// @brief Memory provider settings struct
typedef struct umf_devdax_memory_provider_params_t {
    /// path of the device DAX
    char *path;
    /// size of the device DAX in bytes
    size_t size;
    /// combination of 'umf_mem_protection_flags_t' flags
    unsigned protection;
} umf_devdax_memory_provider_params_t;

/// @brief Devdax Memory Provider operation results
typedef enum umf_devdax_memory_provider_native_error {
    UMF_DEVDAX_RESULT_SUCCESS = UMF_DEVDAX_RESULTS_START_FROM, ///< Success
    UMF_DEVDAX_RESULT_ERROR_ALLOC_FAILED,        ///< Memory allocation failed
    UMF_DEVDAX_RESULT_ERROR_ADDRESS_NOT_ALIGNED, ///< Allocated address is not aligned
    UMF_DEVDAX_RESULT_ERROR_FREE_FAILED,         ///< Memory deallocation failed
    UMF_DEVDAX_RESULT_ERROR_PURGE_FORCE_FAILED, ///< Force purging failed
} umf_devdax_memory_provider_native_error_t;

umf_memory_provider_ops_t *umfDevDaxMemoryProviderOps(void);

/// @brief Create default params for the devdax memory provider
static inline umf_devdax_memory_provider_params_t
umfDevDaxMemoryProviderParamsDefault(char *path, size_t size) {
    umf_devdax_memory_provider_params_t params = {
        path, /* path of the device DAX */
        size, /* size of the device DAX in bytes */
        UMF_PROTECTION_READ | UMF_PROTECTION_WRITE, /* protection */
    };

    return params;
}

#ifdef __cplusplus
}
#endif

#endif /* UMF_DEVDAX_MEMORY_PROVIDER_H */
