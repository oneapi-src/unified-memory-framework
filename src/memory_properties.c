/*
 *
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <inttypes.h>

#include <umf/experimental/memory_properties.h>
#include <umf/providers/provider_cuda.h>
#include <umf/providers/provider_level_zero.h>

#include "memory_properties_internal.h"
#include "memory_provider_internal.h"
#include "provider/provider_tracking.h"

umf_result_t
umfGetMemoryPropertiesHandle(const void *ptr,
                             umf_memory_properties_handle_t *props_handle) {
    UMF_CHECK((props_handle != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);

    tracker_alloc_info_t *info = NULL;
    umf_result_t ret = umfMemoryTrackerGetAllocInfo(ptr, &info);
    if (ret == UMF_RESULT_SUCCESS) {
        *props_handle = &info->props;
        return UMF_RESULT_SUCCESS;
    }

    // try to get IPC info
    umf_ipc_info_t ipc_info;
    ret = umfMemoryTrackerGetIpcInfo(ptr, &ipc_info);
    if (ret == UMF_RESULT_SUCCESS) {
        *props_handle = ipc_info.props;
        return UMF_RESULT_SUCCESS;
    }

    LOG_ERR("Failed to get memory properties handle for ptr=%p", ptr);
    return ret;
}

umf_result_t
umfGetMemoryPropertySize(umf_memory_properties_handle_t props_handle,
                         umf_memory_property_id_t memory_property_id,
                         size_t *size) {
    UMF_CHECK((size != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);

    switch (memory_property_id) {
    case UMF_MEMORY_PROPERTY_INVALID:
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    case UMF_MEMORY_PROPERTY_PROVIDER_HANDLE:
        *size = sizeof(umf_memory_provider_handle_t);
        return UMF_RESULT_SUCCESS;
    case UMF_MEMORY_PROPERTY_POOL_HANDLE:
        *size = sizeof(umf_memory_pool_handle_t);
        return UMF_RESULT_SUCCESS;
    case UMF_MEMORY_PROPERTY_BASE_ADDRESS:
        *size = sizeof(uintptr_t);
        return UMF_RESULT_SUCCESS;
    case UMF_MEMORY_PROPERTY_BASE_SIZE:
        *size = sizeof(size_t);
        return UMF_RESULT_SUCCESS;
    case UMF_MEMORY_PROPERTY_BUFFER_ID:
        *size = sizeof(uint64_t);
        return UMF_RESULT_SUCCESS;
    case UMF_MEMORY_PROPERTY_POINTER_TYPE:
        *size = sizeof(umf_usm_memory_type_t);
        return UMF_RESULT_SUCCESS;
    default:
        break;
    }

    // custom memory properties should be handled by the user provider
    umf_memory_provider_t *provider = props_handle->provider;
    if (provider->ops.ext_get_allocation_properties_size) {
        return provider->ops.ext_get_allocation_properties_size(
            provider->provider_priv, memory_property_id, size);
    }

    LOG_ERR("Unknown memory property ID: %d", memory_property_id);
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

umf_result_t umfGetMemoryProperty(umf_memory_properties_handle_t props_handle,
                                  umf_memory_property_id_t memory_property_id,
                                  void *value, size_t max_property_size) {
    UMF_CHECK((value != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((props_handle != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((max_property_size > 0), UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umf_memory_provider_t *provider = props_handle->provider;

    size_t property_size = 0;
    umf_result_t ret = umfGetMemoryPropertySize(
        props_handle, memory_property_id, &property_size);
    if (UNLIKELY(ret != UMF_RESULT_SUCCESS)) {
        LOG_ERR("Failed to get memory property size for ID %d",
                memory_property_id);
        return ret;
    }

    if (UNLIKELY(property_size > max_property_size)) {
        LOG_ERR("Memory property size %zu exceeds max size %zu for ID %d",
                property_size, max_property_size, memory_property_id);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    switch (memory_property_id) {
    case UMF_MEMORY_PROPERTY_INVALID:
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;

    case UMF_MEMORY_PROPERTY_POOL_HANDLE:
        *(umf_memory_pool_handle_t *)value = props_handle->pool;
        return UMF_RESULT_SUCCESS;

    case UMF_MEMORY_PROPERTY_PROVIDER_HANDLE:
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

    case UMF_MEMORY_PROPERTY_POINTER_TYPE:
        // NOTE: this property is "cached" in the props_handle but the value is
        // determined by the memory provider and set during addition to the
        // tracker.
        *(umf_usm_memory_type_t *)value = props_handle->memory_type;
        return UMF_RESULT_SUCCESS;

    // GPU Memory Provider specific properties - should be handled by the
    // provider
    case UMF_MEMORY_PROPERTY_CONTEXT:
    case UMF_MEMORY_PROPERTY_DEVICE:
    default:
        break;
    };

    // custom memory properties should be handled by the user provider
    if (provider->ops.ext_get_allocation_properties) {
        return provider->ops.ext_get_allocation_properties(
            provider->provider_priv, props_handle->base, memory_property_id,
            value);
    }

    LOG_ERR("Unknown memory property ID: %d", memory_property_id);
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}
