/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <umf.h>
#include <umf/memory_provider_ops.h>
#include <umf/providers/provider_level_zero.h>

#include "utils_log.h"

#if defined(UMF_NO_LEVEL_ZERO_PROVIDER)

umf_result_t umfLevelZeroMemoryProviderParamsCreate(
    umf_level_zero_memory_provider_params_handle_t *hParams) {
    (void)hParams;
    LOG_ERR("L0 memory provider is disabled! (UMF_BUILD_LEVEL_ZERO_PROVIDER is "
            "OFF)");
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

umf_result_t umfLevelZeroMemoryProviderParamsDestroy(
    umf_level_zero_memory_provider_params_handle_t hParams) {
    (void)hParams;
    LOG_ERR("L0 memory provider is disabled! (UMF_BUILD_LEVEL_ZERO_PROVIDER is "
            "OFF)");
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

umf_result_t umfLevelZeroMemoryProviderParamsSetContext(
    umf_level_zero_memory_provider_params_handle_t hParams,
    ze_context_handle_t hContext) {
    (void)hParams;
    (void)hContext;
    LOG_ERR("L0 memory provider is disabled! (UMF_BUILD_LEVEL_ZERO_PROVIDER is "
            "OFF)");
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

umf_result_t umfLevelZeroMemoryProviderParamsSetDevice(
    umf_level_zero_memory_provider_params_handle_t hParams,
    ze_device_handle_t hDevice) {
    (void)hParams;
    (void)hDevice;
    LOG_ERR("L0 memory provider is disabled! (UMF_BUILD_LEVEL_ZERO_PROVIDER is "
            "OFF)");
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

umf_result_t umfLevelZeroMemoryProviderParamsSetMemoryType(
    umf_level_zero_memory_provider_params_handle_t hParams,
    umf_usm_memory_type_t memoryType) {
    (void)hParams;
    (void)memoryType;
    LOG_ERR("L0 memory provider is disabled! (UMF_BUILD_LEVEL_ZERO_PROVIDER is "
            "OFF)");
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

umf_result_t umfLevelZeroMemoryProviderParamsSetResidentDevices(
    umf_level_zero_memory_provider_params_handle_t hParams,
    ze_device_handle_t *hDevices, uint32_t deviceCount) {
    (void)hParams;
    (void)hDevices;
    (void)deviceCount;
    LOG_ERR("L0 memory provider is disabled! (UMF_BUILD_LEVEL_ZERO_PROVIDER is "
            "OFF)");
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

umf_result_t umfLevelZeroMemoryProviderParamsSetFreePolicy(
    umf_level_zero_memory_provider_params_handle_t hParams,
    umf_level_zero_memory_provider_free_policy_t policy) {
    (void)hParams;
    (void)policy;
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

umf_memory_provider_ops_t *umfLevelZeroMemoryProviderOps(void) {
    // not supported
    LOG_ERR("L0 memory provider is disabled! (UMF_BUILD_LEVEL_ZERO_PROVIDER is "
            "OFF)");
    return NULL;
}

#else // !defined(UMF_NO_LEVEL_ZERO_PROVIDER)

#include "base_alloc_global.h"
#include "libumf.h"
#include "utils_assert.h"
#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_load_library.h"
#include "utils_log.h"
#include "utils_sanitizers.h"
#include "ze_api.h"

// Level Zero Memory Provider settings struct
typedef struct umf_level_zero_memory_provider_params_t {
    ze_context_handle_t
        level_zero_context_handle; ///< Handle to the Level Zero context
    ze_device_handle_t
        level_zero_device_handle; ///< Handle to the Level Zero device

    umf_usm_memory_type_t memory_type; ///< Allocation memory type

    ze_device_handle_t *
        resident_device_handles; ///< Array of devices for which the memory should be made resident
    uint32_t
        resident_device_count; ///< Number of devices for which the memory should be made resident

    umf_level_zero_memory_provider_free_policy_t
        freePolicy; ///< Memory free policy
} umf_level_zero_memory_provider_params_t;

typedef struct ze_memory_provider_t {
    ze_context_handle_t context;
    ze_device_handle_t device;
    ze_memory_type_t memory_type;

    ze_device_handle_t *resident_device_handles;
    uint32_t resident_device_count;

    ze_device_properties_t device_properties;

    ze_driver_memory_free_policy_ext_flags_t freePolicyFlags;
} ze_memory_provider_t;

typedef struct ze_ops_t {
    ze_result_t (*zeMemAllocHost)(ze_context_handle_t,
                                  const ze_host_mem_alloc_desc_t *, size_t,
                                  size_t, void *);
    ze_result_t (*zeMemAllocDevice)(ze_context_handle_t,
                                    const ze_device_mem_alloc_desc_t *, size_t,
                                    size_t, ze_device_handle_t, void *);
    ze_result_t (*zeMemAllocShared)(ze_context_handle_t,
                                    const ze_device_mem_alloc_desc_t *,
                                    const ze_host_mem_alloc_desc_t *, size_t,
                                    size_t, ze_device_handle_t, void *);
    ze_result_t (*zeMemFree)(ze_context_handle_t, void *);
    ze_result_t (*zeMemGetIpcHandle)(ze_context_handle_t, const void *,
                                     ze_ipc_mem_handle_t *);
    ze_result_t (*zeMemPutIpcHandle)(ze_context_handle_t, ze_ipc_mem_handle_t);
    ze_result_t (*zeMemOpenIpcHandle)(ze_context_handle_t, ze_device_handle_t,
                                      ze_ipc_mem_handle_t,
                                      ze_ipc_memory_flags_t, void **);
    ze_result_t (*zeMemCloseIpcHandle)(ze_context_handle_t, void *);
    ze_result_t (*zeContextMakeMemoryResident)(ze_context_handle_t,
                                               ze_device_handle_t, void *,
                                               size_t);
    ze_result_t (*zeDeviceGetProperties)(ze_device_handle_t,
                                         ze_device_properties_t *);
    ze_result_t (*zeMemFreeExt)(ze_context_handle_t,
                                ze_memory_free_ext_desc_t *, void *);
} ze_ops_t;

static ze_ops_t g_ze_ops;
static UTIL_ONCE_FLAG ze_is_initialized = UTIL_ONCE_FLAG_INIT;
static bool Init_ze_global_state_failed;
static __TLS ze_result_t TLS_last_native_error;

static void store_last_native_error(int32_t native_error) {
    TLS_last_native_error = native_error;
}

static umf_result_t ze2umf_result(ze_result_t result) {
    switch (result) {
    case ZE_RESULT_SUCCESS:
        return UMF_RESULT_SUCCESS;
    case ZE_RESULT_ERROR_OUT_OF_HOST_MEMORY:
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    case ZE_RESULT_ERROR_INVALID_ARGUMENT:
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    default:
        store_last_native_error(result);
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }
}

static void init_ze_global_state(void) {
#ifdef _WIN32
    const char *lib_name = "ze_loader.dll";
#else
    const char *lib_name = "libze_loader.so";
#endif
    // check if Level Zero shared library is already loaded
    // we pass 0 as a handle to search the global symbol table
    *(void **)&g_ze_ops.zeMemAllocHost =
        utils_get_symbol_addr(0, "zeMemAllocHost", lib_name);
    *(void **)&g_ze_ops.zeMemAllocDevice =
        utils_get_symbol_addr(0, "zeMemAllocDevice", lib_name);
    *(void **)&g_ze_ops.zeMemAllocShared =
        utils_get_symbol_addr(0, "zeMemAllocShared", lib_name);
    *(void **)&g_ze_ops.zeMemFree =
        utils_get_symbol_addr(0, "zeMemFree", lib_name);
    *(void **)&g_ze_ops.zeMemGetIpcHandle =
        utils_get_symbol_addr(0, "zeMemGetIpcHandle", lib_name);
    *(void **)&g_ze_ops.zeMemPutIpcHandle =
        utils_get_symbol_addr(0, "zeMemPutIpcHandle", lib_name);
    *(void **)&g_ze_ops.zeMemOpenIpcHandle =
        utils_get_symbol_addr(0, "zeMemOpenIpcHandle", lib_name);
    *(void **)&g_ze_ops.zeMemCloseIpcHandle =
        utils_get_symbol_addr(0, "zeMemCloseIpcHandle", lib_name);
    *(void **)&g_ze_ops.zeContextMakeMemoryResident =
        utils_get_symbol_addr(0, "zeContextMakeMemoryResident", lib_name);
    *(void **)&g_ze_ops.zeDeviceGetProperties =
        utils_get_symbol_addr(0, "zeDeviceGetProperties", lib_name);
    *(void **)&g_ze_ops.zeMemFreeExt =
        utils_get_symbol_addr(0, "zeMemFreeExt", lib_name);

    if (!g_ze_ops.zeMemAllocHost || !g_ze_ops.zeMemAllocDevice ||
        !g_ze_ops.zeMemAllocShared || !g_ze_ops.zeMemFree ||
        !g_ze_ops.zeMemGetIpcHandle || !g_ze_ops.zeMemOpenIpcHandle ||
        !g_ze_ops.zeMemCloseIpcHandle ||
        !g_ze_ops.zeContextMakeMemoryResident ||
        !g_ze_ops.zeDeviceGetProperties) {
        // g_ze_ops.zeMemPutIpcHandle can be NULL because it was introduced
        // starting from Level Zero 1.6
        LOG_ERR("Required Level Zero symbols not found.");
        Init_ze_global_state_failed = true;
    }
}

umf_result_t umfLevelZeroMemoryProviderParamsCreate(
    umf_level_zero_memory_provider_params_handle_t *hParams) {
    libumfInit();
    if (!hParams) {
        LOG_ERR("Level zero memory provider params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_level_zero_memory_provider_params_t *params =
        umf_ba_global_alloc(sizeof(umf_level_zero_memory_provider_params_t));
    if (!params) {
        LOG_ERR("Cannot allocate memory for Level Zero memory provider params");
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    // Assign default values
    params->level_zero_context_handle = NULL;
    params->level_zero_device_handle = NULL;
    params->memory_type = UMF_MEMORY_TYPE_UNKNOWN;
    params->resident_device_handles = NULL;
    params->resident_device_count = 0;
    params->freePolicy = UMF_LEVEL_ZERO_MEMORY_PROVIDER_FREE_POLICY_DEFAULT;

    *hParams = params;

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfLevelZeroMemoryProviderParamsDestroy(
    umf_level_zero_memory_provider_params_handle_t hParams) {
    umf_ba_global_free(hParams);

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfLevelZeroMemoryProviderParamsSetContext(
    umf_level_zero_memory_provider_params_handle_t hParams,
    ze_context_handle_t hContext) {
    if (!hParams) {
        LOG_ERR("Level zero memory provider params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (!hContext) {
        LOG_ERR("Level zero context handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hParams->level_zero_context_handle = hContext;

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfLevelZeroMemoryProviderParamsSetDevice(
    umf_level_zero_memory_provider_params_handle_t hParams,
    ze_device_handle_t hDevice) {
    if (!hParams) {
        LOG_ERR("Level zero memory provider params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hParams->level_zero_device_handle = hDevice;

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfLevelZeroMemoryProviderParamsSetMemoryType(
    umf_level_zero_memory_provider_params_handle_t hParams,
    umf_usm_memory_type_t memoryType) {
    if (!hParams) {
        LOG_ERR("Level zero memory provider params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hParams->memory_type = memoryType;

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfLevelZeroMemoryProviderParamsSetResidentDevices(
    umf_level_zero_memory_provider_params_handle_t hParams,
    ze_device_handle_t *hDevices, uint32_t deviceCount) {
    if (!hParams) {
        LOG_ERR("Level zero memory provider params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (deviceCount && !hDevices) {
        LOG_ERR("Resident devices array is NULL, but deviceCount is not zero");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hParams->resident_device_handles = hDevices;
    hParams->resident_device_count = deviceCount;

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfLevelZeroMemoryProviderParamsSetFreePolicy(
    umf_level_zero_memory_provider_params_handle_t hParams,
    umf_level_zero_memory_provider_free_policy_t policy) {
    if (!hParams) {
        LOG_ERR("Level zero memory provider params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hParams->freePolicy = policy;
    return UMF_RESULT_SUCCESS;
}

static ze_driver_memory_free_policy_ext_flags_t
umfFreePolicyToZePolicy(umf_level_zero_memory_provider_free_policy_t policy) {
    switch (policy) {
    case UMF_LEVEL_ZERO_MEMORY_PROVIDER_FREE_POLICY_DEFAULT:
        return 0;
    case UMF_LEVEL_ZERO_MEMORY_PROVIDER_FREE_POLICY_BLOCKING_FREE:
        return ZE_DRIVER_MEMORY_FREE_POLICY_EXT_FLAG_BLOCKING_FREE;
    case UMF_LEVEL_ZERO_MEMORY_PROVIDER_FREE_POLICY_DEFER_FREE:
        return ZE_DRIVER_MEMORY_FREE_POLICY_EXT_FLAG_DEFER_FREE;
    default:
        return 0;
    }
}

static umf_result_t ze_memory_provider_initialize(void *params,
                                                  void **provider) {
    if (params == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_level_zero_memory_provider_params_handle_t ze_params =
        (umf_level_zero_memory_provider_params_handle_t)params;

    if (!ze_params->level_zero_context_handle) {
        LOG_ERR("Level Zero context handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if ((ze_params->memory_type == UMF_MEMORY_TYPE_HOST) ==
        (ze_params->level_zero_device_handle != NULL)) {
        LOG_ERR("Level Zero device handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if ((bool)ze_params->resident_device_count &&
        (ze_params->resident_device_handles == NULL)) {
        LOG_ERR("Resident devices handles array is NULL, but device_count is "
                "not zero");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    utils_init_once(&ze_is_initialized, init_ze_global_state);
    if (Init_ze_global_state_failed) {
        LOG_ERR("Loading Level Zero symbols failed");
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    ze_memory_provider_t *ze_provider =
        umf_ba_global_alloc(sizeof(ze_memory_provider_t));
    if (!ze_provider) {
        LOG_ERR("Cannot allocate memory for Level Zero Memory Provider");
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    ze_provider->context = ze_params->level_zero_context_handle;
    ze_provider->device = ze_params->level_zero_device_handle;
    ze_provider->memory_type = (ze_memory_type_t)ze_params->memory_type;
    ze_provider->freePolicyFlags =
        umfFreePolicyToZePolicy(ze_params->freePolicy);

    memset(&ze_provider->device_properties, 0,
           sizeof(ze_provider->device_properties));
    ze_provider->device_properties.stype = ZE_STRUCTURE_TYPE_DEVICE_PROPERTIES;

    if (ze_provider->device) {
        umf_result_t ret = ze2umf_result(g_ze_ops.zeDeviceGetProperties(
            ze_provider->device, &ze_provider->device_properties));

        if (ret != UMF_RESULT_SUCCESS) {
            LOG_ERR("Cannot get device properties");
            umf_ba_global_free(ze_provider);
            return ret;
        }
    }

    if (ze_params->resident_device_count) {
        ze_provider->resident_device_handles = umf_ba_global_alloc(
            sizeof(ze_device_handle_t) * ze_params->resident_device_count);
        if (!ze_provider->resident_device_handles) {
            LOG_ERR("Cannot allocate memory for resident devices");
            umf_ba_global_free(ze_provider);
            return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        }

        ze_provider->resident_device_count = ze_params->resident_device_count;

        for (uint32_t i = 0; i < ze_provider->resident_device_count; i++) {
            ze_provider->resident_device_handles[i] =
                ze_params->resident_device_handles[i];
        }
    } else {
        ze_provider->resident_device_handles = NULL;
        ze_provider->resident_device_count = 0;
    }

    *provider = ze_provider;

    return UMF_RESULT_SUCCESS;
}

static void ze_memory_provider_finalize(void *provider) {
    ze_memory_provider_t *ze_provider = (ze_memory_provider_t *)provider;
    umf_ba_global_free(ze_provider->resident_device_handles);

    umf_ba_global_free(provider);
}

static bool use_relaxed_allocation(ze_memory_provider_t *ze_provider,
                                   size_t size) {
    assert(ze_provider);
    assert(ze_provider->device);
    assert(ze_provider->device_properties.maxMemAllocSize > 0);

    return size > ze_provider->device_properties.maxMemAllocSize;
}

static ze_relaxed_allocation_limits_exp_desc_t relaxed_device_allocation_desc =
    {.stype = ZE_STRUCTURE_TYPE_RELAXED_ALLOCATION_LIMITS_EXP_DESC,
     .pNext = NULL,
     .flags = ZE_RELAXED_ALLOCATION_LIMITS_EXP_FLAG_MAX_SIZE};

static umf_result_t ze_memory_provider_alloc(void *provider, size_t size,
                                             size_t alignment,
                                             void **resultPtr) {
    ze_memory_provider_t *ze_provider = (ze_memory_provider_t *)provider;

    ze_result_t ze_result = ZE_RESULT_SUCCESS;
    switch (ze_provider->memory_type) {
    case UMF_MEMORY_TYPE_HOST: {
        ze_host_mem_alloc_desc_t host_desc = {
            .stype = ZE_STRUCTURE_TYPE_HOST_MEM_ALLOC_DESC,
            .pNext = NULL,
            .flags = 0};
        ze_result = g_ze_ops.zeMemAllocHost(ze_provider->context, &host_desc,
                                            size, alignment, resultPtr);
        break;
    }
    case UMF_MEMORY_TYPE_DEVICE: {
        ze_device_mem_alloc_desc_t dev_desc = {
            .stype = ZE_STRUCTURE_TYPE_DEVICE_MEM_ALLOC_DESC,
            .pNext = use_relaxed_allocation(ze_provider, size)
                         ? &relaxed_device_allocation_desc
                         : NULL,
            .flags = 0,
            .ordinal = 0 // TODO
        };
        ze_result = g_ze_ops.zeMemAllocDevice(ze_provider->context, &dev_desc,
                                              size, alignment,
                                              ze_provider->device, resultPtr);
        break;
    }
    case UMF_MEMORY_TYPE_SHARED: {
        ze_host_mem_alloc_desc_t host_desc = {
            .stype = ZE_STRUCTURE_TYPE_HOST_MEM_ALLOC_DESC,
            .pNext = NULL,
            .flags = 0};
        ze_device_mem_alloc_desc_t dev_desc = {
            .stype = ZE_STRUCTURE_TYPE_DEVICE_MEM_ALLOC_DESC,
            .pNext = use_relaxed_allocation(ze_provider, size)
                         ? &relaxed_device_allocation_desc
                         : NULL,
            .flags = 0,
            .ordinal = 0 // TODO
        };
        ze_result = g_ze_ops.zeMemAllocShared(ze_provider->context, &dev_desc,
                                              &host_desc, size, alignment,
                                              ze_provider->device, resultPtr);
        break;
    }
    default:
        // this shouldn't happen as we check the memory_type settings during
        // the initialization
        LOG_ERR("unsupported USM memory type");
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    if (ze_result != ZE_RESULT_SUCCESS) {
        return ze2umf_result(ze_result);
    }

    for (uint32_t i = 0; i < ze_provider->resident_device_count; i++) {
        ze_result = g_ze_ops.zeContextMakeMemoryResident(
            ze_provider->context, ze_provider->resident_device_handles[i],
            *resultPtr, size);
        if (ze_result != ZE_RESULT_SUCCESS) {
            return ze2umf_result(ze_result);
        }
    }

    return ze2umf_result(ze_result);
}

static umf_result_t ze_memory_provider_free(void *provider, void *ptr,
                                            size_t bytes) {
    (void)bytes;

    if (ptr == NULL) {
        return UMF_RESULT_SUCCESS;
    }

    ze_memory_provider_t *ze_provider = (ze_memory_provider_t *)provider;

    if (ze_provider->freePolicyFlags == 0) {
        return ze2umf_result(g_ze_ops.zeMemFree(ze_provider->context, ptr));
    }

    ze_memory_free_ext_desc_t desc = {
        .stype = ZE_STRUCTURE_TYPE_MEMORY_FREE_EXT_DESC,
        .pNext = NULL,
        .freePolicy = ze_provider->freePolicyFlags};

    return ze2umf_result(
        g_ze_ops.zeMemFreeExt(ze_provider->context, &desc, ptr));
}

static void ze_memory_provider_get_last_native_error(void *provider,
                                                     const char **ppMessage,
                                                     int32_t *pError) {
    (void)provider;

    if (ppMessage == NULL || pError == NULL) {
        ASSERT(0);
        return;
    }

    *pError = TLS_last_native_error;
}

static umf_result_t ze_memory_provider_get_min_page_size(void *provider,
                                                         void *ptr,
                                                         size_t *pageSize) {
    (void)provider;
    (void)ptr;

    // TODO
    *pageSize = 1024 * 64;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t ze_memory_provider_purge_lazy(void *provider, void *ptr,
                                                  size_t size) {
    (void)provider;
    (void)ptr;
    (void)size;

    // TODO not supported yet
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

static umf_result_t ze_memory_provider_purge_force(void *provider, void *ptr,
                                                   size_t size) {
    (void)provider;
    (void)ptr;
    (void)size;

    // TODO not supported yet
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

static umf_result_t
ze_memory_provider_get_recommended_page_size(void *provider, size_t size,
                                             size_t *pageSize) {
    (void)provider;
    (void)size;

    // TODO
    *pageSize = 1024 * 64;
    return UMF_RESULT_SUCCESS;
}

static const char *ze_memory_provider_get_name(void *provider) {
    (void)provider;
    return "LEVEL_ZERO";
}

static umf_result_t ze_memory_provider_allocation_merge(void *hProvider,
                                                        void *lowPtr,
                                                        void *highPtr,
                                                        size_t totalSize) {
    (void)hProvider;
    (void)lowPtr;
    (void)highPtr;
    (void)totalSize;

    // TODO not supported yet
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

static umf_result_t ze_memory_provider_allocation_split(void *provider,
                                                        void *ptr,
                                                        size_t totalSize,
                                                        size_t firstSize) {
    (void)provider;
    (void)ptr;
    (void)totalSize;
    (void)firstSize;

    // TODO not supported yet
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

typedef struct ze_ipc_data_t {
    int pid;
    ze_ipc_mem_handle_t ze_handle;
} ze_ipc_data_t;

static umf_result_t ze_memory_provider_get_ipc_handle_size(void *provider,
                                                           size_t *size) {
    (void)provider;

    *size = sizeof(ze_ipc_data_t);
    return UMF_RESULT_SUCCESS;
}

static umf_result_t ze_memory_provider_get_ipc_handle(void *provider,
                                                      const void *ptr,
                                                      size_t size,
                                                      void *providerIpcData) {
    (void)size;

    ze_result_t ze_result;
    ze_ipc_data_t *ze_ipc_data = (ze_ipc_data_t *)providerIpcData;
    struct ze_memory_provider_t *ze_provider =
        (struct ze_memory_provider_t *)provider;

    ze_result = g_ze_ops.zeMemGetIpcHandle(ze_provider->context, ptr,
                                           &ze_ipc_data->ze_handle);
    if (ze_result != ZE_RESULT_SUCCESS) {
        LOG_ERR("zeMemGetIpcHandle() failed.");
        return ze2umf_result(ze_result);
    }

    ze_ipc_data->pid = utils_getpid();

    return UMF_RESULT_SUCCESS;
}

static umf_result_t ze_memory_provider_put_ipc_handle(void *provider,
                                                      void *providerIpcData) {
    ze_result_t ze_result;
    struct ze_memory_provider_t *ze_provider =
        (struct ze_memory_provider_t *)provider;
    ze_ipc_data_t *ze_ipc_data = (ze_ipc_data_t *)providerIpcData;

    if (g_ze_ops.zeMemPutIpcHandle == NULL) {
        // g_ze_ops.zeMemPutIpcHandle can be NULL because it was introduced
        // starting from Level Zero 1.6. Before Level Zero 1.6 IPC handle
        // is released automatically when corresponding memory buffer is freed.
        return UMF_RESULT_SUCCESS;
    }

    ze_result = g_ze_ops.zeMemPutIpcHandle(ze_provider->context,
                                           ze_ipc_data->ze_handle);
    if (ze_result != ZE_RESULT_SUCCESS) {
        LOG_ERR("zeMemPutIpcHandle() failed.");
        return ze2umf_result(ze_result);
    }
    return UMF_RESULT_SUCCESS;
}

static umf_result_t ze_memory_provider_open_ipc_handle(void *provider,
                                                       void *providerIpcData,
                                                       void **ptr) {
    ze_result_t ze_result;
    ze_ipc_data_t *ze_ipc_data = (ze_ipc_data_t *)providerIpcData;
    struct ze_memory_provider_t *ze_provider =
        (struct ze_memory_provider_t *)provider;
    int fd_local = -1;
    ze_ipc_mem_handle_t ze_ipc_handle = ze_ipc_data->ze_handle;

    if (ze_ipc_data->pid != utils_getpid()) {
        int fd_remote = -1;
        memcpy(&fd_remote, &ze_ipc_handle, sizeof(fd_remote));
        umf_result_t umf_result =
            utils_duplicate_fd(ze_ipc_data->pid, fd_remote, &fd_local);
        if (umf_result != UMF_RESULT_SUCCESS) {
            LOG_PERR("duplicating file descriptor failed");
            return umf_result;
        }
        memcpy(&ze_ipc_handle, &fd_local, sizeof(fd_local));
    }

    ze_result = g_ze_ops.zeMemOpenIpcHandle(
        ze_provider->context, ze_provider->device, ze_ipc_handle, 0, ptr);
    if (fd_local != -1) {
        (void)utils_close_fd(fd_local);
    }
    if (ze_result != ZE_RESULT_SUCCESS) {
        LOG_ERR("zeMemOpenIpcHandle() failed.");
        return ze2umf_result(ze_result);
    }

    return UMF_RESULT_SUCCESS;
}

static umf_result_t
ze_memory_provider_close_ipc_handle(void *provider, void *ptr, size_t size) {
    (void)size;

    ze_result_t ze_result;
    struct ze_memory_provider_t *ze_provider =
        (struct ze_memory_provider_t *)provider;

    ze_result = g_ze_ops.zeMemCloseIpcHandle(ze_provider->context, ptr);
    if (ze_result != ZE_RESULT_SUCCESS) {
        LOG_ERR("zeMemCloseIpcHandle() failed.");
        return ze2umf_result(ze_result);
    }

    return UMF_RESULT_SUCCESS;
}

static struct umf_memory_provider_ops_t UMF_LEVEL_ZERO_MEMORY_PROVIDER_OPS = {
    .version = UMF_VERSION_CURRENT,
    .initialize = ze_memory_provider_initialize,
    .finalize = ze_memory_provider_finalize,
    .alloc = ze_memory_provider_alloc,
    .free = ze_memory_provider_free,
    .get_last_native_error = ze_memory_provider_get_last_native_error,
    .get_recommended_page_size = ze_memory_provider_get_recommended_page_size,
    .get_min_page_size = ze_memory_provider_get_min_page_size,
    .get_name = ze_memory_provider_get_name,
    .ext.purge_lazy = ze_memory_provider_purge_lazy,
    .ext.purge_force = ze_memory_provider_purge_force,
    .ext.allocation_merge = ze_memory_provider_allocation_merge,
    .ext.allocation_split = ze_memory_provider_allocation_split,
    .ipc.get_ipc_handle_size = ze_memory_provider_get_ipc_handle_size,
    .ipc.get_ipc_handle = ze_memory_provider_get_ipc_handle,
    .ipc.put_ipc_handle = ze_memory_provider_put_ipc_handle,
    .ipc.open_ipc_handle = ze_memory_provider_open_ipc_handle,
    .ipc.close_ipc_handle = ze_memory_provider_close_ipc_handle,
};

umf_memory_provider_ops_t *umfLevelZeroMemoryProviderOps(void) {
    return &UMF_LEVEL_ZERO_MEMORY_PROVIDER_OPS;
}

#endif // !defined(UMF_NO_LEVEL_ZERO_PROVIDER)
