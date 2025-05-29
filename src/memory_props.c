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
umfGetMemoryPropertiesHandle(void *ptr,
                             umf_memory_properties_handle_t *props_handle) {
    umf_alloc_info_t allocInfo = {NULL, 0, NULL};
    umf_result_t ret = umfMemoryTrackerGetAllocInfo(ptr, &allocInfo);
    if (ret != UMF_RESULT_SUCCESS) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *props_handle = allocInfo.props;
    return UMF_RESULT_SUCCESS;
}

umf_result_t umfGetMemoryProperty(umf_memory_properties_handle_t props_handle,
                                  umf_memory_property_id_t memory_property_id,
                                  void *value) {
    if ((value == NULL) || (props_handle == NULL)) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    switch (memory_property_id) {
    case UMF_MEMORY_PROPERTY_INVALID:
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;

    case UMF_MEMORY_POOL_HANDLE:
        *(umf_memory_pool_handle_t *)value = props_handle->pool;
        return UMF_RESULT_SUCCESS;

    case UMF_MEMORY_PROVIDER_HANDLE:
        *(umf_memory_provider_handle_t *)value = props_handle->provider;
        return UMF_RESULT_SUCCESS;

    case UMF_MEMORY_PROPERTY_BUFFER_ID:
        *(uint64_t *)value = props_handle->id;
        return UMF_RESULT_SUCCESS;

    // GPU Memory Provider specific properties
    case UMF_MEMORY_PROPERTY_POINTER_TYPE:
    case UMF_MEMORY_PROPERTY_DEVICE:
    case UMF_MEMORY_PROPERTY_DEVICE_ATTRIBUTES:
        // properties that are related to the memory provider
        umf_memory_provider_t *provider = props_handle->provider;
        return provider->ops.ext_get_allocation_properties(
            provider->provider_priv, props_handle, memory_property_id, value);

    default:
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}
