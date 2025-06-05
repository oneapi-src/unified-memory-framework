/*
 *
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <umf/memory_props.h>
#include <umf/providers/provider_cuda.h>
#include <umf/providers/provider_level_zero.h>

#include "memory_props_internal.h"
#include "memory_provider_internal.h"
#include "provider/provider_tracking.h"

umf_result_t
umfGetMemoryPropertiesHandle(const void *ptr,
                             umf_memory_properties_handle_t *props_handle) {

    // TODO remove?
    umf_result_t ret = umfMemoryTrackerGetAllocInfo(ptr, props_handle);
    if (ret != UMF_RESULT_SUCCESS) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfGetMemoryProperty(umf_memory_properties_handle_t props_handle,
                                  umf_memory_property_id_t memory_property_id,
                                  void *value) {
    if ((value == NULL) || (props_handle == NULL)) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_memory_provider_t *provider = props_handle->provider;

    switch (memory_property_id) {
    case UMF_MEMORY_PROPERTY_INVALID:
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;

    case UMF_MEMORY_POOL_HANDLE:
        *(umf_memory_pool_handle_t *)value = props_handle->pool;
        return UMF_RESULT_SUCCESS;

    case UMF_MEMORY_PROVIDER_HANDLE:
        *(umf_memory_provider_handle_t *)value = provider;
        return UMF_RESULT_SUCCESS;

    case UMF_MEMORY_PROPERTY_BUFFER_ID:
        *(uint64_t *)value = props_handle->id;
        return UMF_RESULT_SUCCESS;

    case UMF_MEMORY_PROPERTY_BASE_ADDRESS:
        *(uintptr_t *)value = (uintptr_t)props_handle->base;
        return UMF_RESULT_SUCCESS;

    case UMF_MEMORY_PROPERTY_BASE_SIZE:
        *(size_t *)value = props_handle->base_size;
        return UMF_RESULT_SUCCESS;

    // GPU Memory Provider specific properties
    case UMF_MEMORY_PROPERTY_POINTER_TYPE:
    case UMF_MEMORY_PROPERTY_CONTEXT:
    case UMF_MEMORY_PROPERTY_DEVICE:
        return provider->ops.ext_get_allocation_properties(
            provider->provider_priv, props_handle, memory_property_id, value);

    default:
        break;
    };

    return UMF_RESULT_ERROR_INVALID_ARGUMENT;
}
