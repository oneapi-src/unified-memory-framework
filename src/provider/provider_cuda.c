/*
 * Copyright (C) 2024-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <umf.h>
#include <umf/providers/provider_cuda.h>

#include "memory_provider_internal.h"
#include "provider_ctl_stats_type.h"
#include "provider_cuda_internal.h"
#include "utils_load_library.h"
#include "utils_log.h"

static void *cu_lib_handle = NULL;

void fini_cu_global_state(void) {
    if (cu_lib_handle) {
        utils_close_library(cu_lib_handle);
        cu_lib_handle = NULL;
    }
}

#if UMF_BUILD_CUDA_PROVIDER

// disable warning 4201: nonstandard extension used: nameless struct/union
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4201)
#endif // _MSC_VER

#include "cuda.h"

#if defined(_MSC_VER)
#pragma warning(pop)
#endif // _MSC_VER

#include "base_alloc_global.h"
#include "libumf.h"
#include "utils_assert.h"
#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_log.h"
#include "utils_sanitizers.h"

typedef struct cu_memory_provider_t {
    CUcontext context;
    CUdevice device;
    umf_usm_memory_type_t memory_type;
    size_t min_alignment;
    unsigned int alloc_flags;
    ctl_stats_t stats;
    char name[64];
} cu_memory_provider_t;

#define CTL_PROVIDER_TYPE cu_memory_provider_t
#include "provider_ctl_stats_impl.h"

// CUDA Memory Provider settings struct
typedef struct umf_cuda_memory_provider_params_t {
    // Handle to the CUDA context
    void *cuda_context_handle;

    // Handle to the CUDA device
    int cuda_device_handle;

    // Allocation memory type
    umf_usm_memory_type_t memory_type;

    // Allocation flags for cuMemHostAlloc/cuMemAllocManaged
    unsigned int alloc_flags;
    char name[64];
} umf_cuda_memory_provider_params_t;

typedef struct cu_ops_t {
    CUresult (*cuMemGetAllocationGranularity)(
        size_t *granularity, const CUmemAllocationProp *prop,
        CUmemAllocationGranularity_flags option);
    CUresult (*cuMemAlloc)(CUdeviceptr *dptr, size_t bytesize);
    CUresult (*cuMemHostAlloc)(void **pp, size_t bytesize, unsigned int flags);
    CUresult (*cuMemAllocManaged)(CUdeviceptr *dptr, size_t bytesize,
                                  unsigned int flags);
    CUresult (*cuMemFree)(CUdeviceptr dptr);
    CUresult (*cuMemFreeHost)(void *p);

    CUresult (*cuGetErrorName)(CUresult error, const char **pStr);
    CUresult (*cuGetErrorString)(CUresult error, const char **pStr);
    CUresult (*cuCtxGetCurrent)(CUcontext *pctx);
    CUresult (*cuCtxGetDevice)(CUdevice *device);
    CUresult (*cuCtxSetCurrent)(CUcontext ctx);
    CUresult (*cuIpcGetMemHandle)(CUipcMemHandle *pHandle, CUdeviceptr dptr);
    CUresult (*cuIpcOpenMemHandle)(CUdeviceptr *pdptr, CUipcMemHandle handle,
                                   unsigned int Flags);
    CUresult (*cuIpcCloseMemHandle)(CUdeviceptr dptr);
} cu_ops_t;

typedef CUipcMemHandle cu_ipc_data_t;

static cu_ops_t g_cu_ops;
static UTIL_ONCE_FLAG cu_is_initialized = UTIL_ONCE_FLAG_INIT;
static bool Init_cu_global_state_failed;

struct ctl cu_memory_ctl_root;
static UTIL_ONCE_FLAG ctl_initialized = UTIL_ONCE_FLAG_INIT;

// forward decl needed for alloc
static umf_result_t cu_memory_provider_free(void *provider, void *ptr,
                                            size_t bytes);

#define TLS_MSG_BUF_LEN 1024

static const char *DEFAULT_NAME = "CUDA";

typedef struct cu_last_native_error_t {
    CUresult native_error;
    char msg_buff[TLS_MSG_BUF_LEN];
} cu_last_native_error_t;

static __TLS cu_last_native_error_t TLS_last_native_error;

static void cu_store_last_native_error(CUresult native_error) {
    TLS_last_native_error.native_error = native_error;
}

static umf_result_t cu2umf_result(CUresult result) {
    switch (result) {
    case CUDA_SUCCESS:
        return UMF_RESULT_SUCCESS;
    case CUDA_ERROR_OUT_OF_MEMORY:
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    case CUDA_ERROR_INVALID_VALUE:
    case CUDA_ERROR_INVALID_HANDLE:
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    case CUDA_ERROR_DEINITIALIZED:
        LOG_ERR("CUDA driver has been deinitialized");
        return UMF_RESULT_ERROR_OUT_OF_RESOURCES;
    default:
        cu_store_last_native_error(result);
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }
}

static void initialize_cu_ctl(void) {
    CTL_REGISTER_MODULE(&cu_memory_ctl_root, stats);
}

static void init_cu_global_state(void) {
#ifdef _WIN32
    const char *lib_name = "nvcuda.dll";
#else
    const char *lib_name = "libcuda.so";
#endif
    // The CUDA shared library should be already loaded by the user
    // of the CUDA provider. UMF just want to reuse it
    // and increase the reference count to the CUDA shared library.
    void *lib_handle =
        utils_open_library(lib_name, UMF_UTIL_OPEN_LIBRARY_NO_LOAD);
    if (!lib_handle) {
        LOG_ERR("Failed to open CUDA shared library");
        Init_cu_global_state_failed = true;
        return;
    }

    // NOTE: some symbols defined in the lib have _vX postfixes - it is
    // important to load the proper version of functions
    *(void **)&g_cu_ops.cuMemGetAllocationGranularity = utils_get_symbol_addr(
        lib_handle, "cuMemGetAllocationGranularity", lib_name);
    *(void **)&g_cu_ops.cuMemAlloc =
        utils_get_symbol_addr(lib_handle, "cuMemAlloc_v2", lib_name);
    *(void **)&g_cu_ops.cuMemHostAlloc =
        utils_get_symbol_addr(lib_handle, "cuMemHostAlloc", lib_name);
    *(void **)&g_cu_ops.cuMemAllocManaged =
        utils_get_symbol_addr(lib_handle, "cuMemAllocManaged", lib_name);
    *(void **)&g_cu_ops.cuMemFree =
        utils_get_symbol_addr(lib_handle, "cuMemFree_v2", lib_name);
    *(void **)&g_cu_ops.cuMemFreeHost =
        utils_get_symbol_addr(lib_handle, "cuMemFreeHost", lib_name);
    *(void **)&g_cu_ops.cuGetErrorName =
        utils_get_symbol_addr(lib_handle, "cuGetErrorName", lib_name);
    *(void **)&g_cu_ops.cuGetErrorString =
        utils_get_symbol_addr(lib_handle, "cuGetErrorString", lib_name);
    *(void **)&g_cu_ops.cuCtxGetCurrent =
        utils_get_symbol_addr(lib_handle, "cuCtxGetCurrent", lib_name);
    *(void **)&g_cu_ops.cuCtxGetDevice =
        utils_get_symbol_addr(lib_handle, "cuCtxGetDevice", lib_name);
    *(void **)&g_cu_ops.cuCtxSetCurrent =
        utils_get_symbol_addr(lib_handle, "cuCtxSetCurrent", lib_name);
    *(void **)&g_cu_ops.cuIpcGetMemHandle =
        utils_get_symbol_addr(lib_handle, "cuIpcGetMemHandle", lib_name);
    *(void **)&g_cu_ops.cuIpcOpenMemHandle =
        utils_get_symbol_addr(lib_handle, "cuIpcOpenMemHandle_v2", lib_name);
    *(void **)&g_cu_ops.cuIpcCloseMemHandle =
        utils_get_symbol_addr(lib_handle, "cuIpcCloseMemHandle", lib_name);

    if (!g_cu_ops.cuMemGetAllocationGranularity || !g_cu_ops.cuMemAlloc ||
        !g_cu_ops.cuMemHostAlloc || !g_cu_ops.cuMemAllocManaged ||
        !g_cu_ops.cuMemFree || !g_cu_ops.cuMemFreeHost ||
        !g_cu_ops.cuGetErrorName || !g_cu_ops.cuGetErrorString ||
        !g_cu_ops.cuCtxGetCurrent || !g_cu_ops.cuCtxGetDevice ||
        !g_cu_ops.cuCtxSetCurrent || !g_cu_ops.cuIpcGetMemHandle ||
        !g_cu_ops.cuIpcOpenMemHandle || !g_cu_ops.cuIpcCloseMemHandle) {
        LOG_FATAL("Required CUDA symbols not found.");
        Init_cu_global_state_failed = true;
        utils_close_library(lib_handle);
        return;
    }
    cu_lib_handle = lib_handle;
}

umf_result_t umfCUDAMemoryProviderParamsCreate(
    umf_cuda_memory_provider_params_handle_t *hParams) {
    libumfInit();
    if (!hParams) {
        LOG_ERR("CUDA Memory Provider params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_cuda_memory_provider_params_handle_t params_data =
        umf_ba_global_alloc(sizeof(umf_cuda_memory_provider_params_t));
    if (!params_data) {
        LOG_ERR("Cannot allocate memory for CUDA Memory Provider params");
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    utils_init_once(&cu_is_initialized, init_cu_global_state);
    if (Init_cu_global_state_failed) {
        LOG_FATAL("Loading CUDA symbols failed");
        return UMF_RESULT_ERROR_DEPENDENCY_UNAVAILABLE;
    }

    // initialize context and device to the current ones
    CUcontext current_ctx = NULL;
    CUresult cu_result = g_cu_ops.cuCtxGetCurrent(&current_ctx);
    if (cu_result == CUDA_SUCCESS) {
        params_data->cuda_context_handle = current_ctx;
    } else {
        params_data->cuda_context_handle = NULL;
    }

    CUdevice current_device = -1;
    cu_result = g_cu_ops.cuCtxGetDevice(&current_device);
    if (cu_result == CUDA_SUCCESS) {
        params_data->cuda_device_handle = current_device;
    } else {
        params_data->cuda_device_handle = -1;
    }

    params_data->memory_type = UMF_MEMORY_TYPE_UNKNOWN;
    params_data->alloc_flags = 0;
    strncpy(params_data->name, DEFAULT_NAME, sizeof(params_data->name) - 1);
    params_data->name[sizeof(params_data->name) - 1] = '\0';

    *hParams = params_data;

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfCUDAMemoryProviderParamsDestroy(
    umf_cuda_memory_provider_params_handle_t hParams) {
    umf_ba_global_free(hParams);

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfCUDAMemoryProviderParamsSetContext(
    umf_cuda_memory_provider_params_handle_t hParams, void *hContext) {
    if (!hParams) {
        LOG_ERR("CUDA Memory Provider params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hParams->cuda_context_handle = hContext;

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfCUDAMemoryProviderParamsSetDevice(
    umf_cuda_memory_provider_params_handle_t hParams, int hDevice) {
    if (!hParams) {
        LOG_ERR("CUDA Memory Provider params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hParams->cuda_device_handle = hDevice;

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfCUDAMemoryProviderParamsSetMemoryType(
    umf_cuda_memory_provider_params_handle_t hParams,
    umf_usm_memory_type_t memoryType) {
    if (!hParams) {
        LOG_ERR("CUDA Memory Provider params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hParams->memory_type = memoryType;

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfCUDAMemoryProviderParamsSetAllocFlags(
    umf_cuda_memory_provider_params_handle_t hParams, unsigned int flags) {
    if (!hParams) {
        LOG_ERR("CUDA Memory Provider params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hParams->alloc_flags = flags;

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfCUDAMemoryProviderParamsSetName(
    umf_cuda_memory_provider_params_handle_t hParams, const char *name) {
    if (!hParams) {
        LOG_ERR("CUDA Memory Provider params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (!name) {
        LOG_ERR("name is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    strncpy(hParams->name, name, sizeof(hParams->name) - 1);
    hParams->name[sizeof(hParams->name) - 1] = '\0';

    return UMF_RESULT_SUCCESS;
}

static umf_result_t cu_memory_provider_initialize(const void *params,
                                                  void **provider) {
    if (params == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    const umf_cuda_memory_provider_params_t *cu_params = params;

    if (cu_params->memory_type == UMF_MEMORY_TYPE_UNKNOWN ||
        cu_params->memory_type > UMF_MEMORY_TYPE_SHARED) {
        LOG_ERR("Invalid memory type value");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (cu_params->cuda_context_handle == NULL) {
        LOG_ERR("Invalid context handle");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (cu_params->cuda_device_handle < 0) {
        LOG_ERR("Invalid device handle");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    utils_init_once(&cu_is_initialized, init_cu_global_state);
    if (Init_cu_global_state_failed) {
        LOG_FATAL("Loading CUDA symbols failed");
        return UMF_RESULT_ERROR_DEPENDENCY_UNAVAILABLE;
    }

    cu_memory_provider_t *cu_provider =
        umf_ba_global_alloc(sizeof(cu_memory_provider_t));
    if (!cu_provider) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    memset(cu_provider, 0, sizeof(*cu_provider));
    snprintf(cu_provider->name, sizeof(cu_provider->name), "%s",
             cu_params->name);

    // CUDA alloc functions doesn't allow to provide user alignment - get the
    // minimum one from the driver
    size_t min_alignment = 0;
    CUmemAllocationProp allocProps = {0};
    allocProps.location.type = CU_MEM_LOCATION_TYPE_DEVICE;
    allocProps.type = CU_MEM_ALLOCATION_TYPE_PINNED;
    allocProps.location.id = cu_params->cuda_device_handle;
    CUresult cu_result = g_cu_ops.cuMemGetAllocationGranularity(
        &min_alignment, &allocProps, CU_MEM_ALLOC_GRANULARITY_MINIMUM);
    if (cu_result != CUDA_SUCCESS) {
        umf_ba_global_free(cu_provider);
        return cu2umf_result(cu_result);
    }

    cu_provider->context = cu_params->cuda_context_handle;
    cu_provider->device = cu_params->cuda_device_handle;
    cu_provider->memory_type = cu_params->memory_type;
    cu_provider->min_alignment = min_alignment;

    // If the memory type is shared (CUDA managed), the allocation flags must
    // be set. NOTE: we do not check here if the flags are valid -
    // this will be done by CUDA runtime.
    if (cu_params->memory_type == UMF_MEMORY_TYPE_SHARED &&
        cu_params->alloc_flags == 0) {
        // the default setting is CU_MEM_ATTACH_GLOBAL
        cu_provider->alloc_flags = CU_MEM_ATTACH_GLOBAL;
    } else {
        cu_provider->alloc_flags = cu_params->alloc_flags;
    }

    *provider = cu_provider;

    return UMF_RESULT_SUCCESS;
}

static umf_result_t cu_memory_provider_finalize(void *provider) {
    umf_ba_global_free(provider);
    return UMF_RESULT_SUCCESS;
}

/*
 * This function is used by the CUDA provider to make sure that
 * the required context is set. If the current context is
 * not the required one, it will be saved in restore_ctx.
 */
static inline umf_result_t set_context(CUcontext required_ctx,
                                       CUcontext *restore_ctx) {
    CUcontext current_ctx = NULL;
    CUresult cu_result = g_cu_ops.cuCtxGetCurrent(&current_ctx);
    if (cu_result != CUDA_SUCCESS) {
        LOG_ERR("cuCtxGetCurrent() failed.");
        return cu2umf_result(cu_result);
    }
    *restore_ctx = current_ctx;
    if (current_ctx != required_ctx) {
        cu_result = g_cu_ops.cuCtxSetCurrent(required_ctx);
        if (cu_result != CUDA_SUCCESS) {
            LOG_ERR("cuCtxSetCurrent() failed.");
            return cu2umf_result(cu_result);
        }
    }

    return UMF_RESULT_SUCCESS;
}

static umf_result_t cu_memory_provider_alloc(void *provider, size_t size,
                                             size_t alignment,
                                             void **resultPtr) {
    cu_memory_provider_t *cu_provider = (cu_memory_provider_t *)provider;

    if (alignment > cu_provider->min_alignment) {
        // alignment of CUDA allocations is controlled by the CUDA driver -
        // currently UMF doesn't support alignment larger than default
        return UMF_RESULT_ERROR_NOT_SUPPORTED;
    }

    // Remember current context and set the one from the provider
    CUcontext restore_ctx = NULL;
    umf_result_t umf_result = set_context(cu_provider->context, &restore_ctx);
    if (umf_result != UMF_RESULT_SUCCESS) {
        LOG_ERR("Failed to set CUDA context, ret = %d", umf_result);
        return umf_result;
    }

    CUresult cu_result = CUDA_SUCCESS;
    switch (cu_provider->memory_type) {
    case UMF_MEMORY_TYPE_HOST: {
        cu_result =
            g_cu_ops.cuMemHostAlloc(resultPtr, size, cu_provider->alloc_flags);
        break;
    }
    case UMF_MEMORY_TYPE_DEVICE: {
        cu_result = g_cu_ops.cuMemAlloc((CUdeviceptr *)resultPtr, size);
        break;
    }
    case UMF_MEMORY_TYPE_SHARED: {
        cu_result = g_cu_ops.cuMemAllocManaged((CUdeviceptr *)resultPtr, size,
                                               cu_provider->alloc_flags);
        break;
    }
    default:
        // this shouldn't happen as we check the memory_type settings during
        // the initialization
        LOG_ERR("unsupported USM memory type");
        assert(false);
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    umf_result = set_context(restore_ctx, &restore_ctx);
    if (umf_result != UMF_RESULT_SUCCESS) {
        LOG_ERR("Failed to restore CUDA context, ret = %d", umf_result);
    }

    umf_result = cu2umf_result(cu_result);
    if (umf_result != UMF_RESULT_SUCCESS) {
        LOG_ERR("Failed to allocate memory, cu_result = %d, ret = %d",
                cu_result, umf_result);
        return umf_result;
    }

    // check the alignment
    if (alignment > 0 && ((uintptr_t)(*resultPtr) % alignment) != 0) {
        cu_memory_provider_free(provider, *resultPtr, size);
        LOG_ERR("unsupported alignment size");
        return UMF_RESULT_ERROR_INVALID_ALIGNMENT;
    }

    provider_ctl_stats_alloc(cu_provider, size);
    return umf_result;
}

static umf_result_t cu_memory_provider_free(void *provider, void *ptr,
                                            size_t bytes) {
    (void)bytes;

    if (ptr == NULL) {
        return UMF_RESULT_SUCCESS;
    }

    cu_memory_provider_t *cu_provider = (cu_memory_provider_t *)provider;

    // Remember current context and set the one from the provider
    CUcontext restore_ctx = NULL;
    umf_result_t umf_result = set_context(cu_provider->context, &restore_ctx);
    if (umf_result != UMF_RESULT_SUCCESS) {
        LOG_ERR("Failed to set CUDA context, ret = %d", umf_result);
        return umf_result;
    }

    CUresult cu_result = CUDA_SUCCESS;
    switch (cu_provider->memory_type) {
    case UMF_MEMORY_TYPE_HOST: {
        cu_result = g_cu_ops.cuMemFreeHost(ptr);
        break;
    }
    case UMF_MEMORY_TYPE_SHARED:
    case UMF_MEMORY_TYPE_DEVICE: {
        cu_result = g_cu_ops.cuMemFree((CUdeviceptr)ptr);
        break;
    }
    default:
        // this shouldn't happen as we check the memory_type settings during
        // the initialization
        LOG_ERR("unsupported USM memory type");
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    umf_result = set_context(restore_ctx, &restore_ctx);
    if (umf_result != UMF_RESULT_SUCCESS) {
        LOG_ERR("Failed to restore CUDA context, ret = %d", umf_result);
    }

    umf_result_t ret = cu2umf_result(cu_result);
    if (ret == UMF_RESULT_SUCCESS) {
        provider_ctl_stats_free(cu_provider, bytes);
    }
    return ret;
}

static umf_result_t
cu_memory_provider_get_last_native_error(void *provider, const char **ppMessage,
                                         int32_t *pError) {
    (void)provider;

    if (ppMessage == NULL || pError == NULL) {
        ASSERT(0);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    CUresult result;
    umf_result_t ret = UMF_RESULT_SUCCESS;
    size_t buf_size = 0;
    const char *error_name = NULL;
    const char *error_string = NULL;

    // If the error code is not recognized,
    // CUDA_ERROR_INVALID_VALUE will be returned
    // and error_name will be set to the NULL address.
    result = g_cu_ops.cuGetErrorName(TLS_last_native_error.native_error,
                                     &error_name);
    if (result == CUDA_SUCCESS && error_name != NULL) {
        strncpy(TLS_last_native_error.msg_buff, error_name,
                TLS_MSG_BUF_LEN - 1);
        TLS_last_native_error.msg_buff[TLS_MSG_BUF_LEN - 1] = '\0';
    } else {
        strncpy(TLS_last_native_error.msg_buff, "cuGetErrorName() failed",
                TLS_MSG_BUF_LEN - 1);
        TLS_last_native_error.msg_buff[TLS_MSG_BUF_LEN - 1] = '\0';
        ret = cu2umf_result(result);
    }

    buf_size = strlen(TLS_last_native_error.msg_buff);
    strncat(TLS_last_native_error.msg_buff, " - ",
            TLS_MSG_BUF_LEN - buf_size - 1);
    buf_size = strlen(TLS_last_native_error.msg_buff);

    // If the error code is not recognized,
    // CUDA_ERROR_INVALID_VALUE will be returned
    // and error_string will be set to the NULL address.
    result = g_cu_ops.cuGetErrorString(TLS_last_native_error.native_error,
                                       &error_string);
    if (result == CUDA_SUCCESS && error_string != NULL) {
        strncat(TLS_last_native_error.msg_buff, error_string,
                TLS_MSG_BUF_LEN - buf_size - 1);
    } else {
        strncat(TLS_last_native_error.msg_buff, "cuGetErrorString() failed",
                TLS_MSG_BUF_LEN - buf_size - 1);
        ret = cu2umf_result(result);
    }

    *pError = TLS_last_native_error.native_error;
    *ppMessage = TLS_last_native_error.msg_buff;
    return ret;
}

static umf_result_t cu_memory_provider_get_min_page_size(void *provider,
                                                         const void *ptr,
                                                         size_t *pageSize) {
    (void)ptr;

    cu_memory_provider_t *cu_provider = (cu_memory_provider_t *)provider;

    CUmemAllocationProp allocProps = {0};
    allocProps.location.type = CU_MEM_LOCATION_TYPE_DEVICE;
    allocProps.type = CU_MEM_ALLOCATION_TYPE_PINNED;
    allocProps.location.id = cu_provider->device;

    CUresult cu_result = g_cu_ops.cuMemGetAllocationGranularity(
        pageSize, &allocProps, CU_MEM_ALLOC_GRANULARITY_MINIMUM);

    return cu2umf_result(cu_result);
}

static umf_result_t
cu_memory_provider_get_recommended_page_size(void *provider, size_t size,
                                             size_t *pageSize) {
    (void)size;

    cu_memory_provider_t *cu_provider = (cu_memory_provider_t *)provider;

    CUmemAllocationProp allocProps = {0};
    allocProps.location.type = CU_MEM_LOCATION_TYPE_DEVICE;
    allocProps.type = CU_MEM_ALLOCATION_TYPE_PINNED;
    allocProps.location.id = cu_provider->device;

    CUresult cu_result = g_cu_ops.cuMemGetAllocationGranularity(
        pageSize, &allocProps, CU_MEM_ALLOC_GRANULARITY_RECOMMENDED);

    return cu2umf_result(cu_result);
}

static umf_result_t cu_memory_provider_get_name(void *provider,
                                                const char **name) {
    if (!name) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    if (provider == NULL) {
        *name = DEFAULT_NAME;
        return UMF_RESULT_SUCCESS;
    }
    cu_memory_provider_t *cu_provider = (cu_memory_provider_t *)provider;
    *name = cu_provider->name;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t cu_memory_provider_get_ipc_handle_size(void *provider,
                                                           size_t *size) {
    (void)provider;
    *size = sizeof(cu_ipc_data_t);
    return UMF_RESULT_SUCCESS;
}

static umf_result_t cu_memory_provider_get_ipc_handle(void *provider,
                                                      const void *ptr,
                                                      size_t size,
                                                      void *providerIpcData) {
    (void)provider;
    (void)size;

    CUresult cu_result;
    cu_ipc_data_t *cu_ipc_data = (cu_ipc_data_t *)providerIpcData;

    cu_result = g_cu_ops.cuIpcGetMemHandle(cu_ipc_data, (CUdeviceptr)ptr);
    if (cu_result != CUDA_SUCCESS) {
        LOG_ERR("cuIpcGetMemHandle() failed.");
        return cu2umf_result(cu_result);
    }

    return UMF_RESULT_SUCCESS;
}

static umf_result_t cu_memory_provider_put_ipc_handle(void *provider,
                                                      void *providerIpcData) {
    (void)provider;
    (void)providerIpcData;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t cu_memory_provider_open_ipc_handle(void *provider,
                                                       void *providerIpcData,
                                                       void **ptr) {
    cu_memory_provider_t *cu_provider = (cu_memory_provider_t *)provider;

    CUresult cu_result;
    cu_ipc_data_t *cu_ipc_data = (cu_ipc_data_t *)providerIpcData;

    // Remember current context and set the one from the provider
    CUcontext restore_ctx = NULL;
    umf_result_t umf_result = set_context(cu_provider->context, &restore_ctx);
    if (umf_result != UMF_RESULT_SUCCESS) {
        return umf_result;
    }

    cu_result = g_cu_ops.cuIpcOpenMemHandle((CUdeviceptr *)ptr, *cu_ipc_data,
                                            CU_IPC_MEM_LAZY_ENABLE_PEER_ACCESS);

    if (cu_result != CUDA_SUCCESS) {
        LOG_ERR("cuIpcOpenMemHandle() failed.");
    }

    umf_result = set_context(restore_ctx, &restore_ctx);
    if (umf_result != UMF_RESULT_SUCCESS) {
        LOG_ERR("Failed to restore CUDA context, ret = %d", umf_result);
    }

    return cu2umf_result(cu_result);
}

static umf_result_t
cu_memory_provider_close_ipc_handle(void *provider, void *ptr, size_t size) {
    (void)provider;
    (void)size;

    CUresult cu_result;

    cu_result = g_cu_ops.cuIpcCloseMemHandle((CUdeviceptr)ptr);
    if (cu_result != CUDA_SUCCESS) {
        LOG_ERR("cuIpcCloseMemHandle() failed.");
        return cu2umf_result(cu_result);
    }

    return UMF_RESULT_SUCCESS;
}

static umf_result_t cu_ctl(void *provider, umf_ctl_query_source_t operationType,
                           const char *name, void *arg, size_t size,
                           umf_ctl_query_type_t query_type, va_list args) {
    utils_init_once(&ctl_initialized, initialize_cu_ctl);
    return ctl_query(&cu_memory_ctl_root, provider, operationType, name,
                     query_type, arg, size, args);
}

static umf_result_t cu_memory_provider_get_allocation_properties(
    void *provider, const void *ptr,
    umf_memory_property_id_t memory_property_id, void *value) {

    // unused
    (void)ptr;

    cu_memory_provider_t *cuda_provider = (cu_memory_provider_t *)provider;

    switch (memory_property_id) {
    case UMF_MEMORY_PROPERTY_POINTER_TYPE:
        *(umf_usm_memory_type_t *)value = cuda_provider->memory_type;
        return UMF_RESULT_SUCCESS;

    case UMF_MEMORY_PROPERTY_CONTEXT:
        *(CUcontext *)value = cuda_provider->context;
        return UMF_RESULT_SUCCESS;

    case UMF_MEMORY_PROPERTY_DEVICE:
        *(CUdevice *)value = cuda_provider->device;
        return UMF_RESULT_SUCCESS;

    default:
        break;
    };

    return UMF_RESULT_ERROR_INVALID_ARGUMENT;
}

static umf_result_t cu_memory_provider_get_allocation_properties_size(
    void *provider, umf_memory_property_id_t memory_property_id, size_t *size) {

    // unused
    (void)provider;

    switch (memory_property_id) {
    case UMF_MEMORY_PROPERTY_POINTER_TYPE:
        *size = sizeof(umf_usm_memory_type_t);
        return UMF_RESULT_SUCCESS;

    case UMF_MEMORY_PROPERTY_CONTEXT:
        *size = sizeof(CUcontext);
        return UMF_RESULT_SUCCESS;

    case UMF_MEMORY_PROPERTY_DEVICE:
        *size = sizeof(CUdevice);
        return UMF_RESULT_SUCCESS;

    default:
        break;
    };

    return UMF_RESULT_ERROR_INVALID_ARGUMENT;
}

static umf_memory_provider_ops_t UMF_CUDA_MEMORY_PROVIDER_OPS = {
    .version = UMF_PROVIDER_OPS_VERSION_CURRENT,
    .initialize = cu_memory_provider_initialize,
    .finalize = cu_memory_provider_finalize,
    .alloc = cu_memory_provider_alloc,
    .free = cu_memory_provider_free,
    .get_last_native_error = cu_memory_provider_get_last_native_error,
    .get_recommended_page_size = cu_memory_provider_get_recommended_page_size,
    .get_min_page_size = cu_memory_provider_get_min_page_size,
    .get_name = cu_memory_provider_get_name,
    // TODO
    /*
    .ext_purge_lazy = cu_memory_provider_purge_lazy,
    .ext_purge_force = cu_memory_provider_purge_force,
    .ext_allocation_merge = cu_memory_provider_allocation_merge,
    .ext_allocation_split = cu_memory_provider_allocation_split,
    */
    .ext_get_ipc_handle_size = cu_memory_provider_get_ipc_handle_size,
    .ext_get_ipc_handle = cu_memory_provider_get_ipc_handle,
    .ext_put_ipc_handle = cu_memory_provider_put_ipc_handle,
    .ext_open_ipc_handle = cu_memory_provider_open_ipc_handle,
    .ext_close_ipc_handle = cu_memory_provider_close_ipc_handle,
    .ext_ctl = cu_ctl,
    .ext_get_allocation_properties =
        cu_memory_provider_get_allocation_properties,
    .ext_get_allocation_properties_size =
        cu_memory_provider_get_allocation_properties_size,
};

const umf_memory_provider_ops_t *umfCUDAMemoryProviderOps(void) {
    return &UMF_CUDA_MEMORY_PROVIDER_OPS;
}

#else // !UMF_BUILD_CUDA_PROVIDER

umf_result_t umfCUDAMemoryProviderParamsCreate(
    umf_cuda_memory_provider_params_handle_t *hParams) {
    (void)hParams;
    LOG_ERR("CUDA provider is disabled (UMF_BUILD_CUDA_PROVIDER is OFF)!");
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

umf_result_t umfCUDAMemoryProviderParamsDestroy(
    umf_cuda_memory_provider_params_handle_t hParams) {
    (void)hParams;
    LOG_ERR("CUDA provider is disabled (UMF_BUILD_CUDA_PROVIDER is OFF)!");
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

umf_result_t umfCUDAMemoryProviderParamsSetContext(
    umf_cuda_memory_provider_params_handle_t hParams, void *hContext) {
    (void)hParams;
    (void)hContext;
    LOG_ERR("CUDA provider is disabled (UMF_BUILD_CUDA_PROVIDER is OFF)!");
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

umf_result_t umfCUDAMemoryProviderParamsSetDevice(
    umf_cuda_memory_provider_params_handle_t hParams, int hDevice) {
    (void)hParams;
    (void)hDevice;
    LOG_ERR("CUDA provider is disabled (UMF_BUILD_CUDA_PROVIDER is OFF)!");
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

umf_result_t umfCUDAMemoryProviderParamsSetMemoryType(
    umf_cuda_memory_provider_params_handle_t hParams,
    umf_usm_memory_type_t memoryType) {
    (void)hParams;
    (void)memoryType;
    LOG_ERR("CUDA provider is disabled (UMF_BUILD_CUDA_PROVIDER is OFF)!");
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

umf_result_t umfCUDAMemoryProviderParamsSetAllocFlags(
    umf_cuda_memory_provider_params_handle_t hParams, unsigned int flags) {
    (void)hParams;
    (void)flags;
    LOG_ERR("CUDA provider is disabled (UMF_BUILD_CUDA_PROVIDER is OFF)!");
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

umf_result_t umfCUDAMemoryProviderParamsSetName(
    umf_cuda_memory_provider_params_handle_t hParams, const char *name) {
    (void)hParams;
    (void)name;
    LOG_ERR("CUDA provider is disabled (UMF_BUILD_CUDA_PROVIDER is OFF)!");
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

const umf_memory_provider_ops_t *umfCUDAMemoryProviderOps(void) {
    // not supported
    LOG_ERR("CUDA provider is disabled (UMF_BUILD_CUDA_PROVIDER is OFF)!");
    return NULL;
}

#endif // !UMF_BUILD_CUDA_PROVIDER
