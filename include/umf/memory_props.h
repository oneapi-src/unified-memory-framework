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
#include <umf/memory_pool.h>

#ifdef __cplusplus
extern "C" {
#endif

/// @brief TODO
// write about experimental api
typedef enum umf_memory_property_id_t {
    UMF_MEMORY_PROPERTY_INVALID = -1, ///< TODO

    // UMF specyfic
    UMF_MEMORY_PROVIDER_HANDLE,
    UMF_MEMORY_PROVIDER_OPS, // == type?
    UMF_MEMORY_POOL_HANDLE,
    UMF_MEMORY_POOL_OPS, // == type?

    // generic pointer properties
    UMF_MEMORY_PROPERTY_POINTER_TYPE, // unreg host, reg host ??, dev, managed or umf_usm_memory_type_t?
    UMF_MEMORY_PROPERTY_BASE_ADDRESS, // base address
    UMF_MEMORY_PROPERTY_BASE_SIZE,    // base size

    // GPU specyfic
    UMF_MEMORY_PROPERTY_DEVICE, // handle (ze) or id (cuda)
    UMF_MEMORY_PROPERTY_BUFFER_ID, // unique id NOTE: this id is unique across all UMF allocs and != L0 or CUDA ID
    UMF_MEMORY_PROPERTY_DEVICE_ATTRIBUTES, // ze_memory_allocation_properties_t ?

    // all cuda + l0
    // next other providers?
    // todo return type?

    /// @cond
    UMF_MEMORY_PROPERTY_MAX_RESERVED = 0x1000, ///< Maximum reserved value
    /// @endcond

} umf_memory_property_id_t;

typedef struct umf_memory_properties_t *umf_memory_properties_handle_t;

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
