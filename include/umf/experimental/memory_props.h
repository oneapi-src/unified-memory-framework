/*
 *
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_MEMORY_PROPS_H
#define UMF_MEMORY_PROPS_H 1

#include <umf/base.h>

#ifdef __cplusplus
extern "C" {
#endif

/// @brief Get the memory properties handle for a given pointer
/// \details
///     The handle returned by this function is valid until the memory pointed
///     to by the pointer is freed.
/// @param ptr pointer to the allocated memory
/// @param props_handle [out] pointer to the memory properties handle
/// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure
umf_result_t
umfGetMemoryPropertiesHandle(const void *ptr,
                             umf_memory_properties_handle_t *props_handle);

/// @brief Get a specific memory property from the properties handle
/// @param props_handle handle to the memory properties
/// @param memory_property_id ID of the memory property to get
/// @param max_property_size size of the property value buffer
/// @param property_value [out] pointer to the value of the memory property
///         which will be filled
/// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure
umf_result_t umfGetMemoryProperty(umf_memory_properties_handle_t props_handle,
                                  umf_memory_property_id_t memory_property_id,
                                  size_t max_property_size,
                                  void *property_value);

#ifdef __cplusplus
}
#endif

#endif /* UMF_MEMORY_PROPS_H */
