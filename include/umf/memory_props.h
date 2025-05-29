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

/// @brief TODO
umf_result_t
umfGetMemoryPropertiesHandle(void *ptr,
                             umf_memory_properties_handle_t *props_handle);

/// @brief TODO
umf_result_t umfGetMemoryProperty(umf_memory_properties_handle_t props_handle,
                                  umf_memory_property_id_t memory_property_id,
                                  void *value);

#ifdef __cplusplus
}
#endif

#endif /* UMF_MEMORY_PROPS_H */
