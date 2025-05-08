/*
 *
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <umf/memory_props.h>
#include <umf/providers/provider_level_zero.h>

#include "memory_props_internal.h"
#include "memory_provider_internal.h"
#include "provider/provider_level_zero_internal.h"
#include "provider/provider_tracking.h"

umf_result_t
umfGetMemoryProperty(void *ptr, umf_memory_property_id_t memory_property_id,
                     umf_memory_properties_handle_t props_handle /* optional */,
                     void *value) {

    if ((ptr == NULL) || (value == NULL) ||
        (memory_property_id == UMF_MEMORY_PROPERTY_INVALID) ||
        (memory_property_id >= UMF_MEMORY_PROPERTY_MAX_RESERVED)) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_memory_properties_handle_t props = NULL;
    if (props_handle != NULL) {
        props = props_handle;
    } else {
        umf_alloc_info_t allocInfo = {NULL, 0, NULL};
        umf_result_t ret = umfMemoryTrackerGetAllocInfo(ptr, &allocInfo);
        if (ret != UMF_RESULT_SUCCESS) {
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
        props = allocInfo.props;
    }

    switch (memory_property_id) {
    case UMF_MEMORY_PROPERTIES_HANDLE:
        *(umf_memory_properties_handle_t *)value = props;
        return UMF_RESULT_SUCCESS;

    case UMF_MEMORY_POOL_HANDLE:
        *(umf_memory_pool_handle_t *)value = props->pool;
        return UMF_RESULT_SUCCESS;

    case UMF_MEMORY_PROPERTY_BUFFER_ID:
        *(uint64_t *)value = props->id;
        return UMF_RESULT_SUCCESS;

    default:
        break;
    }

    // properties that are related to the memory provider
    umf_memory_provider_t *provider = NULL;
    umfPoolGetMemoryProvider(props->pool, &provider);
    assert(provider != NULL);

    switch (memory_property_id) {
    case UMF_MEMORY_PROPERTY_POINTER_TYPE:
        if (provider->ops.get_name(provider) ==
            umfLevelZeroMemoryProviderOps()->get_name(provider)) {
            ze_memory_provider_t *ze_provider =
                (ze_memory_provider_t *)provider->provider_priv;
            *(umf_usm_memory_type_t *)value = ze_provider->memory_type;
            return UMF_RESULT_SUCCESS;
        }
        break;

    case UMF_MEMORY_PROPERTY_DEVICE:
        if (provider->ops.get_name(provider) ==
            umfLevelZeroMemoryProviderOps()->get_name(provider)) {
            ze_memory_provider_t *ze_provider =
                (ze_memory_provider_t *)provider->provider_priv;
            *(ze_device_handle_t *)value = ze_provider->device;
            return UMF_RESULT_SUCCESS;
        }
        break;

    case UMF_MEMORY_PROPERTY_DEVICE_ATTRIBUTES:
        if (provider->ops.get_name(provider) ==
            umfLevelZeroMemoryProviderOps()->get_name(provider)) {
            // TODO comment
            if (props->gpu_properties_initialized == false) {
                ze_memory_provider_t *ze_provider =
                    (ze_memory_provider_t *)provider->provider_priv;
                props->gpu.ze_properties.stype =
                    ZE_STRUCTURE_TYPE_MEMORY_ALLOCATION_PROPERTIES;
                ze_provider->ze_ops->zeMemGetAllocProperties(
                    ze_provider->context, ptr, &props->gpu.ze_properties, NULL);
                props->gpu_properties_initialized = true;
            }
            ze_memory_allocation_properties_t *ze_properties =
                &props->gpu.ze_properties;
            *(ze_memory_allocation_properties_t **)value = ze_properties;
            return UMF_RESULT_SUCCESS;
        }
        break;

    default:
        return UMF_RESULT_ERROR_NOT_SUPPORTED;
    }

    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}
