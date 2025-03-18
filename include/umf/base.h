/*
 *
 * Copyright (C) 2023-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_BASE_H
#define UMF_BASE_H 1

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// @brief Generates generic 'UMF' API versions
#define UMF_MAKE_VERSION(_major, _minor)                                       \
    ((_major << 16) | (_minor & 0x0000ffff))

/// @brief Extracts 'UMF' API major version
#define UMF_MAJOR_VERSION(_ver) (_ver >> 16)

/// @brief Extracts 'UMF' API minor version
#define UMF_MINOR_VERSION(_ver) (_ver & 0x0000ffff)

/// @brief Current version of the UMF headers
#define UMF_VERSION_CURRENT UMF_MAKE_VERSION(0, 11)

/// @brief Operation results
typedef enum umf_result_t {
    UMF_RESULT_SUCCESS = 0, ///< Success
    UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY =
        1, ///< Insufficient host memory to satisfy call
    UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC =
        2, /*!< A provider specific warning/error has been reported and can be
              Retrieved via the umfMemoryProviderGetLastNativeError entry point. */
    UMF_RESULT_ERROR_INVALID_ARGUMENT =
        3, ///< Generic error code for invalid arguments
    UMF_RESULT_ERROR_INVALID_ALIGNMENT =
        4,                              ///< Invalid alignment of an argument
    UMF_RESULT_ERROR_NOT_SUPPORTED = 5, ///< Operation not supported
    UMF_RESULT_ERROR_USER_SPECIFIC =
        6, ///< Failure in user provider code (i.e in user provided callback)
    UMF_RESULT_ERROR_DEPENDENCY_UNAVAILABLE =
        7, ///< External required dependency is unavailable or missing
    UMF_RESULT_ERROR_OUT_OF_RESOURCES = 8, ///< Out of internal resources
    UMF_RESULT_ERROR_UNKNOWN = 0x7ffffffe  ///< Unknown error
} umf_result_t;

/// @brief Type of the CTL query
typedef enum umf_ctl_query_type {
    CTL_QUERY_READ,
    CTL_QUERY_WRITE,
    CTL_QUERY_RUNNABLE,
    CTL_QUERY_SUBTREE,

    MAX_CTL_QUERY_TYPE
} umf_ctl_query_type_t;

///
/// @brief Get value of a specified attribute at the given name.
/// @param name name of an attribute to be retrieved
/// @param ctx pointer to the pool or the provider
/// @param arg [out] pointer to the variable where the value will be stored
/// @return UMF_RESULT_SUCCESS on success or UMF_RESULT_ERROR_UNKNOWN on failure.
///
umf_result_t umfCtlGet(const char *name, void *ctx, void *arg);

///
/// @brief Set value of a specified attribute at the given name.
/// @param name name of an attribute to be set
/// @param ctx pointer to the pool or the provider
/// @param arg [in] pointer to the value that will be set
/// @return UMF_RESULT_SUCCESS on success or UMF_RESULT_ERROR_UNKNOWN on failure.
///
umf_result_t umfCtlSet(const char *name, void *ctx, void *arg);

///
/// @brief Execute callback related with the specified attribute.
/// @param name name of an attribute to be executed
/// @param ctx pointer to the pool or the provider
/// @param arg [in/out] pointer to the value, can be used as an input or output
/// @return UMF_RESULT_SUCCESS on success or UMF_RESULT_ERROR_UNKNOWN on failure.
///
umf_result_t umfCtlExec(const char *name, void *ctx, void *arg);

#ifdef __cplusplus
}
#endif

#endif /* UMF_BASE_H */
