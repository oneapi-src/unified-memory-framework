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
#include <umf/providers/provider_cuda.h>

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
} cu_memory_provider_t;

typedef struct cu_ops_t {
    // alloc/free memory on device
    CUresult (*cuMemAlloc)(CUdeviceptr *dptr, size_t bytesize);
    CUresult (*cuMemFree)(CUdeviceptr dptr);
    // alloc/free shared memory visible on host and device
    CUresult (*cuMemAllocHost)(void **pp, size_t bytesize);
    CUresult (*cuMemFreeHost)(void *p);
} cu_ops_t;

static cu_ops_t g_cu_ops;
static UTIL_ONCE_FLAG cu_is_initialized = UTIL_ONCE_FLAG_INIT;
static bool Init_cu_global_state_failed;

static void init_cu_global_state(void) {
#ifdef _WIN32
    const char *lib_name = "cudart.dll";
#else
    const char *lib_name = "libcuda.so";
#endif
    // check if CUDA shared library is already loaded
    // we pass 0 as a handle to search the global symbol table

    // NOTE: some symbols defined in the lib have _vX postfixes - this is
    // important to load the proper version of functions
    *(void **)&g_cu_ops.cuMemAlloc =
        util_get_symbol_addr(0, "cuMemAlloc_v2", lib_name);
    *(void **)&g_cu_ops.cuMemFree =
        util_get_symbol_addr(0, "cuMemFree_v2", lib_name);
    *(void **)&g_cu_ops.cuMemAllocHost =
        util_get_symbol_addr(0, "cuMemAllocHost_v2", lib_name);
    *(void **)&g_cu_ops.cuMemFreeHost =
        util_get_symbol_addr(0, "cuMemFreeHost", lib_name);

    if (!g_cu_ops.cuMemAlloc || !g_cu_ops.cuMemFree ||
        !g_cu_ops.cuMemAllocHost || !g_cu_ops.cuMemFreeHost) {
        LOG_ERR("Required CUDA symbols not found.");
        Init_cu_global_state_failed = true;
    }
}

umf_result_t cu_memory_provider_initialize(void *params, void **provider) {
    if (provider == NULL || params == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    cuda_memory_provider_params_t *cu_params =
        (cuda_memory_provider_params_t *)params;

    util_init_once(&cu_is_initialized, init_cu_global_state);
    if (Init_cu_global_state_failed) {
        LOG_ERR("Loading CUDA symbols failed");
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    cu_memory_provider_t *cu_provider =
        umf_ba_global_alloc(sizeof(cu_memory_provider_t));
    if (!cu_provider) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    cu_provider->context = cu_params->cuda_context_handle;
    cu_provider->device = cu_params->cuda_device_handle;
    cu_provider->memory_type = cu_params->memory_type;

    *provider = cu_provider;

    return UMF_RESULT_SUCCESS;
}

void cu_memory_provider_finalize(void *provider) {
    assert(provider);

    util_init_once(&cu_is_initialized, init_cu_global_state);
    umf_ba_global_free(provider);

    // portable version of "cu_is_initialized = UTIL_ONCE_FLAG_INIT;"
    static UTIL_ONCE_FLAG is_initialized = UTIL_ONCE_FLAG_INIT;
    memcpy(&cu_is_initialized, &is_initialized, sizeof(cu_is_initialized));
}

static umf_result_t cu_memory_provider_alloc(void *provider, size_t size,
                                             size_t alignment,
                                             void **resultPtr) {
    assert(provider);
    assert(resultPtr);

    cu_memory_provider_t *cu_provider = (cu_memory_provider_t *)provider;

    CUresult cu_result = CUDA_SUCCESS;
    switch (cu_provider->memory_type) {
    case UMF_MEMORY_TYPE_HOST: {
        // for host-only allocations use ba_alloc
        *resultPtr = umf_ba_global_aligned_alloc(size, alignment);
        if (*resultPtr == NULL) {
            cu_result = CUDA_ERROR_OUT_OF_MEMORY;
        }
        break;
    }
    case UMF_MEMORY_TYPE_DEVICE: {
        cu_result = g_cu_ops.cuMemAlloc((CUdeviceptr *)resultPtr, size);
        break;
    }
    case UMF_MEMORY_TYPE_SHARED: {
        // NOTE: cuMemAllocHost allocates memory that is accessible to the
        // device
        cu_result = g_cu_ops.cuMemAllocHost(resultPtr, size);
        break;
    }
    default:
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    // TODO add error reporting
    return (cu_result == CUDA_SUCCESS)
               ? UMF_RESULT_SUCCESS
               : UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
}

static umf_result_t cu_memory_provider_free(void *provider, void *ptr,
                                            size_t bytes) {
    (void)bytes;

    assert(provider);
    cu_memory_provider_t *cu_provider = (cu_memory_provider_t *)provider;

    CUresult cu_result = CUDA_SUCCESS;
    switch (cu_provider->memory_type) {
    case UMF_MEMORY_TYPE_HOST: {
        umf_ba_global_free(ptr);
        break;
    }
    case UMF_MEMORY_TYPE_DEVICE: {
        cu_result = g_cu_ops.cuMemFree((CUdeviceptr)ptr);
        break;
    }
    case UMF_MEMORY_TYPE_SHARED: {
        cu_result = g_cu_ops.cuMemFreeHost(ptr);
        break;
    }
    default:
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    // TODO add error reporting
    return (cu_result == CUDA_SUCCESS)
               ? UMF_RESULT_SUCCESS
               : UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
}

void cu_memory_provider_get_last_native_error(void *provider,
                                              const char **ppMessage,
                                              int32_t *pError) {
    (void)provider;
    (void)ppMessage;

    // TODO
    assert(pError);
    *pError = 0;
}

static umf_result_t cu_memory_provider_get_min_page_size(void *provider,
                                                         void *ptr,
                                                         size_t *pageSize) {
    (void)provider;
    (void)ptr;

    // TODO
    *pageSize = 1024 * 64;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t
cu_memory_provider_get_recommended_page_size(void *provider, size_t size,
                                             size_t *pageSize) {
    (void)provider;
    (void)size;

    // TODO
    *pageSize = 1024 * 64;
    return UMF_RESULT_SUCCESS;
}

const char *cu_memory_provider_get_name(void *provider) {
    (void)provider;
    return "CUDA";
}

static struct umf_memory_provider_ops_t UMF_CUDA_MEMORY_PROVIDER_OPS = {
    .version = UMF_VERSION_CURRENT,
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
    .ext.purge_lazy = cu_memory_provider_purge_lazy,
    .ext.purge_force = cu_memory_provider_purge_force,
    .ext.allocation_merge = cu_memory_provider_allocation_merge,
    .ext.allocation_split = cu_memory_provider_allocation_split,
    .ipc.get_ipc_handle_size = cu_memory_provider_get_ipc_handle_size,
    .ipc.get_ipc_handle = cu_memory_provider_get_ipc_handle,
    .ipc.put_ipc_handle = cu_memory_provider_put_ipc_handle,
    .ipc.open_ipc_handle = cu_memory_provider_open_ipc_handle,
    .ipc.close_ipc_handle = cu_memory_provider_close_ipc_handle,
    */
};

umf_memory_provider_ops_t *umfCUDAMemoryProviderOps(void) {
    return &UMF_CUDA_MEMORY_PROVIDER_OPS;
}
