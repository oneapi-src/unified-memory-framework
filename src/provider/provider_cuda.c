/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <umf.h>
#include <umf/providers/provider_cuda.h>

#if defined(UMF_NO_CUDA_PROVIDER)

umf_memory_provider_ops_t *umfCUDAMemoryProviderOps(void) {
    // not supported
    return NULL;
}

#else // !defined(UMF_NO_CUDA_PROVIDER)

#include "cuda.h"

#include "base_alloc_global.h"
#include "utils_assert.h"
#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_load_library.h"
#include "utils_log.h"
#include "utils_sanitizers.h"

typedef struct cu_memory_provider_t {
    CUcontext context;
    CUdevice device;
    umf_usm_memory_type_t memory_type;
    size_t min_alignment;
} cu_memory_provider_t;

typedef struct cu_ops_t {
    CUresult (*cuMemGetAllocationGranularity)(
        size_t *granularity, const CUmemAllocationProp *prop,
        CUmemAllocationGranularity_flags option);
    CUresult (*cuMemAlloc)(CUdeviceptr *dptr, size_t bytesize);
    CUresult (*cuMemAllocHost)(void **pp, size_t bytesize);
    CUresult (*cuMemAllocManaged)(CUdeviceptr *dptr, size_t bytesize,
                                  unsigned int flags);
    CUresult (*cuMemFree)(CUdeviceptr dptr);
    CUresult (*cuMemFreeHost)(void *p);

    CUresult (*cuGetErrorName)(CUresult error, const char **pStr);
    CUresult (*cuGetErrorString)(CUresult error, const char **pStr);
    CUresult (*cuCtxGetCurrent)(CUcontext *pctx);
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

// forward decl needed for alloc
static umf_result_t cu_memory_provider_free(void *provider, void *ptr,
                                            size_t bytes);

#define TLS_MSG_BUF_LEN 1024

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
    case CUDA_ERROR_INVALID_RESOURCE_TYPE:
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    default:
        cu_store_last_native_error(result);
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }
}

static void init_cu_global_state(void) {
#ifdef _WIN32
    const char *lib_name = "cudart.dll";
#else
    const char *lib_name = "libcuda.so";
#endif
    // check if CUDA shared library is already loaded
    // we pass 0 as a handle to search the global symbol table

    // NOTE: some symbols defined in the lib have _vX postfixes - it is
    // important to load the proper version of functions
    *(void **)&g_cu_ops.cuMemGetAllocationGranularity =
        utils_get_symbol_addr(0, "cuMemGetAllocationGranularity", lib_name);
    *(void **)&g_cu_ops.cuMemAlloc =
        utils_get_symbol_addr(0, "cuMemAlloc_v2", lib_name);
    *(void **)&g_cu_ops.cuMemAllocHost =
        utils_get_symbol_addr(0, "cuMemAllocHost_v2", lib_name);
    *(void **)&g_cu_ops.cuMemAllocManaged =
        utils_get_symbol_addr(0, "cuMemAllocManaged", lib_name);
    *(void **)&g_cu_ops.cuMemFree =
        utils_get_symbol_addr(0, "cuMemFree_v2", lib_name);
    *(void **)&g_cu_ops.cuMemFreeHost =
        utils_get_symbol_addr(0, "cuMemFreeHost", lib_name);
    *(void **)&g_cu_ops.cuGetErrorName =
        utils_get_symbol_addr(0, "cuGetErrorName", lib_name);
    *(void **)&g_cu_ops.cuGetErrorString =
        utils_get_symbol_addr(0, "cuGetErrorString", lib_name);
    *(void **)&g_cu_ops.cuCtxGetCurrent =
        utils_get_symbol_addr(0, "cuCtxGetCurrent", lib_name);
    *(void **)&g_cu_ops.cuCtxSetCurrent =
        utils_get_symbol_addr(0, "cuCtxSetCurrent", lib_name);
    *(void **)&g_cu_ops.cuIpcGetMemHandle =
        utils_get_symbol_addr(0, "cuIpcGetMemHandle", lib_name);
    *(void **)&g_cu_ops.cuIpcOpenMemHandle =
        utils_get_symbol_addr(0, "cuIpcOpenMemHandle_v2", lib_name);
    *(void **)&g_cu_ops.cuIpcCloseMemHandle =
        utils_get_symbol_addr(0, "cuIpcCloseMemHandle", lib_name);

    if (!g_cu_ops.cuMemGetAllocationGranularity || !g_cu_ops.cuMemAlloc ||
        !g_cu_ops.cuMemAllocHost || !g_cu_ops.cuMemAllocManaged ||
        !g_cu_ops.cuMemFree || !g_cu_ops.cuMemFreeHost ||
        !g_cu_ops.cuGetErrorName || !g_cu_ops.cuGetErrorString ||
        !g_cu_ops.cuCtxGetCurrent || !g_cu_ops.cuCtxSetCurrent ||
        !g_cu_ops.cuIpcGetMemHandle || !g_cu_ops.cuIpcOpenMemHandle ||
        !g_cu_ops.cuIpcCloseMemHandle) {
        LOG_ERR("Required CUDA symbols not found.");
        Init_cu_global_state_failed = true;
    }
}

static umf_result_t cu_memory_provider_initialize(void *params,
                                                  void **provider) {
    if (provider == NULL || params == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    cuda_memory_provider_params_t *cu_params =
        (cuda_memory_provider_params_t *)params;

    if (cu_params->memory_type == UMF_MEMORY_TYPE_UNKNOWN ||
        cu_params->memory_type > UMF_MEMORY_TYPE_SHARED) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (cu_params->cuda_context_handle == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    utils_init_once(&cu_is_initialized, init_cu_global_state);
    if (Init_cu_global_state_failed) {
        LOG_ERR("Loading CUDA symbols failed");
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    cu_memory_provider_t *cu_provider =
        umf_ba_global_alloc(sizeof(cu_memory_provider_t));
    if (!cu_provider) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    // CUDA alloc functions doesn't allow to provide user alignment - get the
    // minimum one from the driver
    size_t min_alignment = 0;
    CUmemAllocationProp allocProps = {0};
    allocProps.location.type = CU_MEM_LOCATION_TYPE_DEVICE;
    allocProps.type = CU_MEM_ALLOCATION_TYPE_PINNED;
    allocProps.location.id = cu_provider->device;
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

    *provider = cu_provider;

    return UMF_RESULT_SUCCESS;
}

static void cu_memory_provider_finalize(void *provider) {
    if (provider == NULL) {
        ASSERT(0);
        return;
    }

    umf_ba_global_free(provider);
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
    if (provider == NULL || resultPtr == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

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
        cu_result = g_cu_ops.cuMemAllocHost(resultPtr, size);
        break;
    }
    case UMF_MEMORY_TYPE_DEVICE: {
        cu_result = g_cu_ops.cuMemAlloc((CUdeviceptr *)resultPtr, size);
        break;
    }
    case UMF_MEMORY_TYPE_SHARED: {
        cu_result = g_cu_ops.cuMemAllocManaged((CUdeviceptr *)resultPtr, size,
                                               CU_MEM_ATTACH_GLOBAL);
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
    return umf_result;
}

static umf_result_t cu_memory_provider_free(void *provider, void *ptr,
                                            size_t bytes) {
    (void)bytes;

    if (provider == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (ptr == NULL) {
        return UMF_RESULT_SUCCESS;
    }

    cu_memory_provider_t *cu_provider = (cu_memory_provider_t *)provider;

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

    return cu2umf_result(cu_result);
}

static void cu_memory_provider_get_last_native_error(void *provider,
                                                     const char **ppMessage,
                                                     int32_t *pError) {
    (void)provider;

    if (ppMessage == NULL || pError == NULL) {
        ASSERT(0);
        return;
    }

    const char *error_name = 0;
    const char *error_string = 0;
    g_cu_ops.cuGetErrorName(TLS_last_native_error.native_error, &error_name);
    g_cu_ops.cuGetErrorString(TLS_last_native_error.native_error,
                              &error_string);

    size_t buf_size = 0;
    strncpy(TLS_last_native_error.msg_buff, error_name, TLS_MSG_BUF_LEN - 1);
    buf_size = strlen(TLS_last_native_error.msg_buff);

    strncat(TLS_last_native_error.msg_buff, " - ",
            TLS_MSG_BUF_LEN - buf_size - 1);
    buf_size = strlen(TLS_last_native_error.msg_buff);

    strncat(TLS_last_native_error.msg_buff, error_string,
            TLS_MSG_BUF_LEN - buf_size - 1);

    *pError = TLS_last_native_error.native_error;
    *ppMessage = TLS_last_native_error.msg_buff;
}

static umf_result_t cu_memory_provider_get_min_page_size(void *provider,
                                                         void *ptr,
                                                         size_t *pageSize) {
    (void)ptr;

    if (provider == NULL || pageSize == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

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

    if (provider == NULL || pageSize == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    cu_memory_provider_t *cu_provider = (cu_memory_provider_t *)provider;

    CUmemAllocationProp allocProps = {0};
    allocProps.location.type = CU_MEM_LOCATION_TYPE_DEVICE;
    allocProps.type = CU_MEM_ALLOCATION_TYPE_PINNED;
    allocProps.location.id = cu_provider->device;

    CUresult cu_result = g_cu_ops.cuMemGetAllocationGranularity(
        pageSize, &allocProps, CU_MEM_ALLOC_GRANULARITY_RECOMMENDED);

    return cu2umf_result(cu_result);
}

static const char *cu_memory_provider_get_name(void *provider) {
    (void)provider;
    return "CUDA";
}

static umf_result_t cu_memory_provider_get_ipc_handle_size(void *provider,
                                                           size_t *size) {
    if (provider == NULL || size == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *size = sizeof(cu_ipc_data_t);
    return UMF_RESULT_SUCCESS;
}

static umf_result_t cu_memory_provider_get_ipc_handle(void *provider,
                                                      const void *ptr,
                                                      size_t size,
                                                      void *providerIpcData) {
    (void)size;

    if (provider == NULL || ptr == NULL || providerIpcData == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

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
    if (provider == NULL || providerIpcData == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    return UMF_RESULT_SUCCESS;
}

static umf_result_t cu_memory_provider_open_ipc_handle(void *provider,
                                                       void *providerIpcData,
                                                       void **ptr) {
    if (provider == NULL || ptr == NULL || providerIpcData == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

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

    set_context(restore_ctx, &restore_ctx);

    return cu2umf_result(cu_result);
}

static umf_result_t
cu_memory_provider_close_ipc_handle(void *provider, void *ptr, size_t size) {
    (void)size;

    if (provider == NULL || ptr == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    CUresult cu_result;

    cu_result = g_cu_ops.cuIpcCloseMemHandle((CUdeviceptr)ptr);
    if (cu_result != CUDA_SUCCESS) {
        LOG_ERR("cuIpcCloseMemHandle() failed.");
        return cu2umf_result(cu_result);
    }

    return UMF_RESULT_SUCCESS;
}

static struct umf_memory_provider_ops_t UMF_CUDA_MEMORY_PROVIDER_OPS = {
    .version = UMF_VERSION_CURRENT,
    .initialize = cu_memory_provider_initialize,
    .finalize = cu_memory_provider_finalize,
    .alloc = cu_memory_provider_alloc,
    .get_last_native_error = cu_memory_provider_get_last_native_error,
    .get_recommended_page_size = cu_memory_provider_get_recommended_page_size,
    .get_min_page_size = cu_memory_provider_get_min_page_size,
    .get_name = cu_memory_provider_get_name,
    .ext.free = cu_memory_provider_free,
    // TODO
    /*
    .ext.purge_lazy = cu_memory_provider_purge_lazy,
    .ext.purge_force = cu_memory_provider_purge_force,
    .ext.allocation_merge = cu_memory_provider_allocation_merge,
    .ext.allocation_split = cu_memory_provider_allocation_split,
    */
    .ipc.get_ipc_handle_size = cu_memory_provider_get_ipc_handle_size,
    .ipc.get_ipc_handle = cu_memory_provider_get_ipc_handle,
    .ipc.put_ipc_handle = cu_memory_provider_put_ipc_handle,
    .ipc.open_ipc_handle = cu_memory_provider_open_ipc_handle,
    .ipc.close_ipc_handle = cu_memory_provider_close_ipc_handle,
};

umf_memory_provider_ops_t *umfCUDAMemoryProviderOps(void) {
    return &UMF_CUDA_MEMORY_PROVIDER_OPS;
}

#endif // !defined(UMF_NO_CUDA_PROVIDER)
