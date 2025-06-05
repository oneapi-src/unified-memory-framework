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

/// @brief TODO
typedef struct umf_memory_properties_t *umf_memory_properties_handle_t;

/// @brief
typedef enum umf_memory_property_id_t {
    UMF_MEMORY_PROPERTY_INVALID = -1, ///< Invalid property

    // UMF specific
    UMF_MEMORY_PROVIDER_HANDLE = 0, ///< Handle to the memory provider
    UMF_MEMORY_POOL_HANDLE = 1,     ///< Handle to the memory pool

    // generic pointer properties
    UMF_MEMORY_PROPERTY_POINTER_TYPE =
        2, ///< Type of the pointer (umf_usm_memory_type_t)
    UMF_MEMORY_PROPERTY_BASE_ADDRESS = 3, ///< Base address of the allocation
    UMF_MEMORY_PROPERTY_BASE_SIZE = 4,    ///< Base size of the allocation
    UMF_MEMORY_PROPERTY_BUFFER_ID = 5,    ///< Unique identifier for the buffer

    // GPU specific
    UMF_MEMORY_PROPERTY_CONTEXT = 6, ///< GPU context of the allocation
    UMF_MEMORY_PROPERTY_DEVICE = 7, ///< GPU device where the allocation resides

    // all cuda + l0
    // next other providers?
    // TODO return type?

    /// @cond
    UMF_MEMORY_PROPERTY_MAX_RESERVED = 0x1000, ///< Maximum reserved value
    /// @endcond
} umf_memory_property_id_t;

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
/// @param size size of the value, depends on the context
/// @return UMF_RESULT_SUCCESS on success or UMF_RESULT_ERROR_UNKNOWN on failure.
///
umf_result_t umfCtlGet(const char *name, void *ctx, void *arg, size_t size);

///
/// @brief Set value of a specified attribute at the given name.
/// @param name name of an attribute to be set
/// @param ctx pointer to the pool or the provider, NULL for the 'default' path
/// @param arg [in] pointer to the value that will be set
/// @param size [in] size of the value, depends on the context
/// @return UMF_RESULT_SUCCESS on success or UMF_RESULT_ERROR_UNKNOWN on failure.
///
umf_result_t umfCtlSet(const char *name, void *ctx, void *arg, size_t size);

///
/// @brief Execute callback related with the specified attribute.
/// @param name name of an attribute to be executed
/// @param ctx pointer to the pool or the provider
/// @param arg [in/out] pointer to the value, can be used as an input or output
/// @param size [in] size of the value, depends on the context
/// @return UMF_RESULT_SUCCESS on success or UMF_RESULT_ERROR_UNKNOWN on failure.
///
umf_result_t umfCtlExec(const char *name, void *ctx, void *arg, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* UMF_BASE_H */
