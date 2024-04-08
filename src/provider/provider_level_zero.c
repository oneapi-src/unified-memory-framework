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

// Level Zero API
#include <ze_api.h>

#include <umf.h>
#include <umf/memory_provider_ops.h>
#include <umf/providers/provider_level_zero.h>

#include "base_alloc_global.h"
#include "utils_assert.h"
#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_load_library.h"
#include "utils_log.h"
#include "utils_sanitizers.h"

typedef struct ze_memory_provider_t {
    ze_context_handle_t context;
    ze_device_handle_t device;
    ze_memory_type_t memory_type;
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
} ze_ops_t;

static ze_ops_t g_ze_ops;
static UTIL_ONCE_FLAG ze_is_initialized = UTIL_ONCE_FLAG_INIT;
static bool Init_ze_global_state_failed;

static void init_ze_global_state(void) {
#ifdef _WIN32
    const char *lib_name = "ze_loader.dll";
#else
    const char *lib_name = "libze_loader.so";
#endif
    // check if Level Zero shared library is already loaded
    // we pass 0 as a handle to search the global symbol table
    *(void **)&g_ze_ops.zeMemAllocHost =
        util_get_symbol_addr(0, "zeMemAllocHost", lib_name);
    *(void **)&g_ze_ops.zeMemAllocDevice =
        util_get_symbol_addr(0, "zeMemAllocDevice", lib_name);
    *(void **)&g_ze_ops.zeMemAllocShared =
        util_get_symbol_addr(0, "zeMemAllocShared", lib_name);
    *(void **)&g_ze_ops.zeMemFree =
        util_get_symbol_addr(0, "zeMemFree", lib_name);
    *(void **)&g_ze_ops.zeMemGetIpcHandle =
        util_get_symbol_addr(0, "zeMemGetIpcHandle", lib_name);
    *(void **)&g_ze_ops.zeMemPutIpcHandle =
        util_get_symbol_addr(0, "zeMemPutIpcHandle", lib_name);
    *(void **)&g_ze_ops.zeMemOpenIpcHandle =
        util_get_symbol_addr(0, "zeMemOpenIpcHandle", lib_name);
    *(void **)&g_ze_ops.zeMemCloseIpcHandle =
        util_get_symbol_addr(0, "zeMemCloseIpcHandle", lib_name);

    if (!g_ze_ops.zeMemAllocHost || !g_ze_ops.zeMemAllocDevice ||
        !g_ze_ops.zeMemAllocShared || !g_ze_ops.zeMemFree ||
        !g_ze_ops.zeMemGetIpcHandle || !g_ze_ops.zeMemOpenIpcHandle ||
        !g_ze_ops.zeMemCloseIpcHandle) {
        // g_ze_ops.zeMemPutIpcHandle can be NULL because it was introduced
        // starting from Level Zero 1.6
        LOG_ERR("Required Level Zero symbols not found.");
        Init_ze_global_state_failed = true;
    }
}

enum umf_result_t ze_memory_provider_initialize(void *params, void **provider) {
    if (provider == NULL || params == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    level_zero_memory_provider_params_t *ze_params =
        (level_zero_memory_provider_params_t *)params;

    util_init_once(&ze_is_initialized, init_ze_global_state);
    if (Init_ze_global_state_failed) {
        LOG_ERR("Loading Level Zero symbols failed");
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    ze_memory_provider_t *ze_provider =
        umf_ba_global_alloc(sizeof(ze_memory_provider_t));
    if (!ze_provider) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    ze_provider->context = ze_params->level_zero_context_handle;
    ze_provider->device = ze_params->level_zero_device_handle;
    ze_provider->memory_type = (ze_memory_type_t)ze_params->memory_type;

    *provider = ze_provider;

    return UMF_RESULT_SUCCESS;
}

void ze_memory_provider_finalize(void *provider) {
    assert(provider);

    util_init_once(&ze_is_initialized, init_ze_global_state);
    umf_ba_global_free(provider);
}

static enum umf_result_t ze_memory_provider_alloc(void *provider, size_t size,
                                                  size_t alignment,
                                                  void **resultPtr) {
    assert(provider);
    assert(resultPtr);

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
            .stype = ZE_STRUCTURE_TYPE_HOST_MEM_ALLOC_DESC,
            .pNext = NULL,
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
            .stype = ZE_STRUCTURE_TYPE_HOST_MEM_ALLOC_DESC,
            .pNext = NULL,
            .flags = 0,
            .ordinal = 0 // TODO
        };
        ze_result = g_ze_ops.zeMemAllocShared(ze_provider->context, &dev_desc,
                                              &host_desc, size, alignment,
                                              ze_provider->device, resultPtr);
        break;
    }
    default:
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    // TODO add error reporting
    return (ze_result == ZE_RESULT_SUCCESS)
               ? UMF_RESULT_SUCCESS
               : UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
}

static enum umf_result_t ze_memory_provider_free(void *provider, void *ptr,
                                                 size_t bytes) {
    (void)bytes;

    assert(provider);
    ze_memory_provider_t *ze_provider = (ze_memory_provider_t *)provider;
    ze_result_t ze_result = g_ze_ops.zeMemFree(ze_provider->context, ptr);

    // TODO add error reporting
    return (ze_result == ZE_RESULT_SUCCESS)
               ? UMF_RESULT_SUCCESS
               : UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
}

void ze_memory_provider_get_last_native_error(void *provider,
                                              const char **ppMessage,
                                              int32_t *pError) {
    (void)provider;
    (void)ppMessage;

    // TODO
    assert(pError);
    *pError = 0;
}

static enum umf_result_t
ze_memory_provider_get_min_page_size(void *provider, void *ptr,
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

static enum umf_result_t
ze_memory_provider_get_recommended_page_size(void *provider, size_t size,
                                             size_t *pageSize) {
    (void)provider;
    (void)size;

    // TODO
    *pageSize = 1024 * 64;
    return UMF_RESULT_SUCCESS;
}

const char *ze_memory_provider_get_name(void *provider) {
    (void)provider;
    return "LEVEL_ZERO";
}

static enum umf_result_t ze_memory_provider_allocation_merge(void *hProvider,
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

struct ipc_data_t {
    ze_ipc_mem_handle_t ze_ipc_handle;
    ze_memory_type_t memory_type;
    //TODO: do we need size?
    size_t size;
};

static umf_result_t ze_memory_provider_get_ipc_handle_size(void *provider,
                                                           size_t *size) {
    (void)provider;
    ASSERT(size != NULL);
    *size = sizeof(struct ipc_data_t);
    return UMF_RESULT_SUCCESS;
}

static umf_result_t ze_memory_provider_get_ipc_handle(void *provider,
                                                      const void *ptr,
                                                      size_t size,
                                                      void *providerIpcData) {
    ASSERT(ptr != NULL);
    ASSERT(providerIpcData != NULL);
    ze_result_t ze_result;
    ze_ipc_mem_handle_t ze_ipc_handle = {0};
    struct ipc_data_t *ipc_data = (struct ipc_data_t *)providerIpcData;
    struct ze_memory_provider_t *ze_provider =
        (struct ze_memory_provider_t *)provider;

    ze_result =
        g_ze_ops.zeMemGetIpcHandle(ze_provider->context, ptr, &ze_ipc_handle);
    if (ze_result != ZE_RESULT_SUCCESS) {
        LOG_ERR("zeMemGetIpcHandle() failed.");
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    memcpy(&(ipc_data->ze_ipc_handle), &ze_ipc_handle,
           sizeof(ze_ipc_mem_handle_t));
    ipc_data->memory_type = ze_provider->memory_type;
    ipc_data->size = size;

    return UMF_RESULT_SUCCESS;
}

static umf_result_t ze_memory_provider_put_ipc_handle(void *provider,
                                                      void *providerIpcData) {
    ASSERT(provider != NULL);
    ASSERT(providerIpcData != NULL);
    ze_result_t ze_result;
    struct ze_memory_provider_t *ze_provider =
        (struct ze_memory_provider_t *)provider;
    struct ipc_data_t *ipc_data = (struct ipc_data_t *)providerIpcData;

    if (g_ze_ops.zeMemPutIpcHandle == NULL) {
        // g_ze_ops.zeMemPutIpcHandle can be NULL because it was introduced
        // starting from Level Zero 1.6. Before Level Zero 1.6 IPC handle
        // is released automatically when corresponding memory buffer is freed.
        return UMF_RESULT_SUCCESS;
    }

    ze_result = g_ze_ops.zeMemPutIpcHandle(ze_provider->context,
                                           ipc_data->ze_ipc_handle);
    if (ze_result != ZE_RESULT_SUCCESS) {
        LOG_ERR("zeMemPutIpcHandle() failed.");
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }
    return UMF_RESULT_SUCCESS;
}

static umf_result_t ze_memory_provider_open_ipc_handle(void *provider,
                                                       void *providerIpcData,
                                                       void **ptr) {
    ASSERT(provider != NULL);
    ASSERT(providerIpcData != NULL);
    ASSERT(ptr != NULL);
    ze_result_t ze_result;
    struct ipc_data_t *ipc_data = (struct ipc_data_t *)providerIpcData;
    struct ze_memory_provider_t *ze_provider =
        (struct ze_memory_provider_t *)provider;

    ze_result =
        g_ze_ops.zeMemOpenIpcHandle(ze_provider->context, ze_provider->device,
                                    ipc_data->ze_ipc_handle, 0, ptr);
    if (ze_result != ZE_RESULT_SUCCESS) {
        LOG_ERR("zeMemOpenIpcHandle() failed.");
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    return UMF_RESULT_SUCCESS;
}

static umf_result_t
ze_memory_provider_close_ipc_handle(void *provider, void *ptr, size_t size) {
    ASSERT(provider != NULL);
    ASSERT(ptr != NULL);
    (void)size;
    ze_result_t ze_result;
    struct ze_memory_provider_t *ze_provider =
        (struct ze_memory_provider_t *)provider;

    ze_result = g_ze_ops.zeMemCloseIpcHandle(ze_provider->context, ptr);
    if (ze_result != ZE_RESULT_SUCCESS) {
        LOG_ERR("zeMemCloseIpcHandle() failed.");
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
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
