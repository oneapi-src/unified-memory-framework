/*
 *
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <inttypes.h>

#include <umf/memory_props.h>
#include <umf/providers/provider_cuda.h>
#include <umf/providers/provider_level_zero.h>

#include "memory_props_internal.h"
#include "memory_provider_internal.h"
#include "provider/provider_tracking.h"

umf_result_t
umfGetMemoryPropertiesHandle(const void *ptr,
                             umf_memory_properties_handle_t *props_handle) {

    LOG_DEBUG("umfGetMemoryPropertiesHandle: ptr=%p, props_handle=%p", ptr,
              props_handle);

    if (props_handle == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    tracker_alloc_info_t *info = NULL;
    umf_result_t ret = umfMemoryTrackerGetAllocInfo(ptr, &info);

    if (ret == UMF_RESULT_SUCCESS) {
        *props_handle = &info->props;
        LOG_DEBUG("umfGetMemoryPropertiesHandle: props_handle=%p, id=%" PRIu64,
                  *props_handle, (*props_handle)->id);
        return UMF_RESULT_SUCCESS;
    }

    // try to get IPC info
    umf_ipc_info_t ipc_info;
    ret = umfMemoryTrackerGetIpcInfo(ptr, &ipc_info);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("Failed to get memory properties handle for ptr=%p", ptr);
        return ret;
    }

    *props_handle = ipc_info.props;
    LOG_DEBUG(
        "umfGetMemoryPropertiesHandle (IPC info): props_handle=%p, id=%" PRIu64,
        *props_handle, (*props_handle)->id);

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfGetMemoryProperty(umf_memory_properties_handle_t props_handle,
                                  umf_memory_property_id_t memory_property_id,
                                  size_t max_property_size, void *value) {

    LOG_DEBUG("umfGetMemoryProperty: props_handle=%p, memory_property_id=%d, "
              "max_property_size=%zu, value=%p",
              props_handle, memory_property_id, max_property_size, value);

    if ((value == NULL) || (props_handle == NULL) || (max_property_size == 0)) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_memory_provider_t *provider = props_handle->provider;

    LOG_DEBUG("umfGetMemoryProperty: provider=%p", provider);
    LOG_DEBUG("dereferencing value...");

    LOG_DEBUG("value: %zu", *(size_t *)value);

    switch (memory_property_id) {
    case UMF_MEMORY_PROPERTY_INVALID:
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;

    case UMF_MEMORY_PROPERTY_POOL_HANDLE:
        if (max_property_size < sizeof(umf_memory_pool_handle_t)) {
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
        *(umf_memory_pool_handle_t *)value = props_handle->pool;
        return UMF_RESULT_SUCCESS;

    case UMF_MEMORY_PROPERTY_PROVIDER_HANDLE:
        if (max_property_size < sizeof(umf_memory_provider_handle_t)) {
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
        *(umf_memory_provider_handle_t *)value = provider;
        return UMF_RESULT_SUCCESS;

    case UMF_MEMORY_PROPERTY_BUFFER_ID:
        if (max_property_size < sizeof(uint64_t)) {
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
        *(uint64_t *)value = props_handle->id;
        return UMF_RESULT_SUCCESS;

    case UMF_MEMORY_PROPERTY_BASE_ADDRESS:
        if (max_property_size < sizeof(uintptr_t)) {
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
        *(uintptr_t *)value = (uintptr_t)props_handle->base;
        return UMF_RESULT_SUCCESS;

    case UMF_MEMORY_PROPERTY_BASE_SIZE:
        if (max_property_size < sizeof(size_t)) {
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
        *(size_t *)value = props_handle->base_size;
        return UMF_RESULT_SUCCESS;

    // GPU Memory Provider specific properties
    case UMF_MEMORY_PROPERTY_POINTER_TYPE:
    case UMF_MEMORY_PROPERTY_CONTEXT:
    case UMF_MEMORY_PROPERTY_DEVICE:
        return provider->ops.ext_get_allocation_properties(
            provider->provider_priv, props_handle->ptr, memory_property_id,
            max_property_size, value);

    default:
        break;
    };

    return UMF_RESULT_ERROR_INVALID_ARGUMENT;
}
