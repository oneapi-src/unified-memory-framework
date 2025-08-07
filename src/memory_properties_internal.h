/*
 *
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_MEMORY_PROPERTIES_INTERNAL_H
#define UMF_MEMORY_PROPERTIES_INTERNAL_H 1

#include <stdbool.h>

#include <umf/experimental/memory_properties.h>
#include <umf/memory_pool.h>
#include <umf/memory_provider.h>
#include <umf/memory_provider_gpu.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct umf_memory_properties_t {
    umf_memory_pool_handle_t pool;
    umf_memory_provider_handle_t provider;
    uint64_t id;
    void *base;
    size_t base_size;
    umf_usm_memory_type_t memory_type;
} umf_memory_properties_t;

umf_result_t umfMemoryProviderGetAllocationProperties(
    umf_memory_provider_handle_t hProvider, const void *ptr,
    umf_memory_property_id_t propertyId, void *property_value);

umf_result_t umfMemoryProviderGetAllocationPropertiesSize(
    umf_memory_provider_handle_t hProvider, umf_memory_property_id_t propertyId,
    size_t *size);

#ifdef __cplusplus
}
#endif

#endif // UMF_MEMORY_PROPERTIES_INTERNAL_H
