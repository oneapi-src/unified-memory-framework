/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base_alloc_global.h"
#include "provider_devdax_memory_internal.h"
#include "provider_os_memory_internal.h"
#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_log.h"

#include <umf.h>
#include <umf/memory_provider_ops.h>
#include <umf/providers/provider_devdax_memory.h>

#define NODESET_STR_BUF_LEN 1024

#define TLS_MSG_BUF_LEN 1024

typedef struct devdax_last_native_error_t {
    int32_t native_error;
    int errno_value;
    char msg_buff[TLS_MSG_BUF_LEN];
} devdax_last_native_error_t;

static __TLS devdax_last_native_error_t TLS_last_native_error;

// helper values used only in the Native_error_str array
#define _UMF_DEVDAX_RESULT_SUCCESS                                             \
    (UMF_DEVDAX_RESULT_SUCCESS - UMF_DEVDAX_RESULT_SUCCESS)
#define _UMF_DEVDAX_RESULT_ERROR_ALLOC_FAILED                                  \
    (UMF_DEVDAX_RESULT_ERROR_ALLOC_FAILED - UMF_DEVDAX_RESULT_SUCCESS)
#define _UMF_DEVDAX_RESULT_ERROR_ADDRESS_NOT_ALIGNED                           \
    (UMF_DEVDAX_RESULT_ERROR_ADDRESS_NOT_ALIGNED - UMF_DEVDAX_RESULT_SUCCESS)
#define _UMF_DEVDAX_RESULT_ERROR_FREE_FAILED                                   \
    (UMF_DEVDAX_RESULT_ERROR_FREE_FAILED - UMF_DEVDAX_RESULT_SUCCESS)
#define _UMF_DEVDAX_RESULT_ERROR_PURGE_FORCE_FAILED                            \
    (UMF_DEVDAX_RESULT_ERROR_PURGE_FORCE_FAILED - UMF_DEVDAX_RESULT_SUCCESS)

static const char *Native_error_str[] = {
    [_UMF_DEVDAX_RESULT_SUCCESS] = "success",
    [_UMF_DEVDAX_RESULT_ERROR_ALLOC_FAILED] = "memory allocation failed",
    [_UMF_DEVDAX_RESULT_ERROR_ADDRESS_NOT_ALIGNED] =
        "allocated address is not aligned",
    [_UMF_DEVDAX_RESULT_ERROR_FREE_FAILED] = "memory deallocation failed",
    [_UMF_DEVDAX_RESULT_ERROR_PURGE_FORCE_FAILED] = "force purging failed",
};

static void devdax_store_last_native_error(int32_t native_error,
                                           int errno_value) {
    TLS_last_native_error.native_error = native_error;
    TLS_last_native_error.errno_value = errno_value;
}

static umf_result_t
devdax_translate_params(umf_devdax_memory_provider_params_t *in_params,
                        devdax_memory_provider_t *provider) {
    umf_result_t result;

    result = os_translate_mem_protection_flags(in_params->protection,
                                               &provider->protection);
    if (result != UMF_RESULT_SUCCESS) {
        LOG_ERR("incorrect memory protection flags: %u", in_params->protection);
        return result;
    }

    return UMF_RESULT_SUCCESS;
}

static umf_result_t devdax_initialize(void *params, void **provider) {
    umf_result_t ret;

    if (provider == NULL || params == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_devdax_memory_provider_params_t *in_params =
        (umf_devdax_memory_provider_params_t *)params;

    if (in_params->path == NULL) {
        LOG_ERR("devdax path is missing");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (in_params->size == 0) {
        LOG_ERR("devdax size is 0");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    devdax_memory_provider_t *devdax_provider =
        umf_ba_global_alloc(sizeof(*devdax_provider));
    if (!devdax_provider) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    memset(devdax_provider, 0, sizeof(*devdax_provider));

    ret = devdax_translate_params(in_params, devdax_provider);
    if (ret != UMF_RESULT_SUCCESS) {
        goto err_free_devdax_provider;
    }

    devdax_provider->size = in_params->size;
    if (util_copy_path(in_params->path, devdax_provider->path, PATH_MAX)) {
        goto err_free_devdax_provider;
    }

    int fd = os_devdax_open(in_params->path);
    if (fd == -1) {
        LOG_ERR("cannot open the device DAX: %s", in_params->path);
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err_free_devdax_provider;
    }

    devdax_provider->base = os_devdax_mmap(NULL, devdax_provider->size,
                                           devdax_provider->protection, fd);
    utils_close_fd(fd);
    if (devdax_provider->base == NULL) {
        LOG_PDEBUG("devdax memory mapping failed (path=%s, size=%zu)",
                   in_params->path, devdax_provider->size);
        ret = UMF_RESULT_ERROR_UNKNOWN;
        goto err_free_devdax_provider;
    }

    LOG_DEBUG("devdax memory mapped (path=%s, size=%zu, addr=%p)",
              in_params->path, devdax_provider->size, devdax_provider->base);

    if (util_mutex_init(&devdax_provider->lock) == NULL) {
        LOG_ERR("lock init failed");
        ret = UMF_RESULT_ERROR_UNKNOWN;
        goto err_unmap_devdax;
    }

    *provider = devdax_provider;

    return UMF_RESULT_SUCCESS;

err_unmap_devdax:
    os_munmap(devdax_provider->base, devdax_provider->size);
err_free_devdax_provider:
    umf_ba_global_free(devdax_provider);
    return ret;
}

static void devdax_finalize(void *provider) {
    if (provider == NULL) {
        assert(0);
        return;
    }

    devdax_memory_provider_t *devdax_provider = provider;
    util_mutex_destroy_not_free(&devdax_provider->lock);
    os_munmap(devdax_provider->base, devdax_provider->size);
    umf_ba_global_free(devdax_provider);
}

static int devdax_alloc_aligned(size_t length, size_t alignment, void *base,
                                size_t size, os_mutex_t *lock, void **out_addr,
                                size_t *offset) {
    assert(out_addr);

    if (util_mutex_lock(lock)) {
        LOG_ERR("locking file offset failed");
        return -1;
    }

    uintptr_t ptr = (uintptr_t)base + *offset;
    uintptr_t rest_of_div = alignment ? (ptr % alignment) : 0;

    if (alignment > 0 && rest_of_div > 0) {
        ptr += alignment - rest_of_div;
    }

    size_t new_offset = ptr - (uintptr_t)base + length;

    if (new_offset > size) {
        util_mutex_unlock(lock);
        LOG_ERR("cannot allocate more memory than the device DAX size: %zu",
                size);
        return -1;
    }

    *offset = new_offset;
    *out_addr = (void *)ptr;

    util_mutex_unlock(lock);

    return 0;
}

static umf_result_t devdax_alloc(void *provider, size_t size, size_t alignment,
                                 void **resultPtr) {
    int ret;

    if (provider == NULL || resultPtr == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    // alignment must be a power of two and a multiple of sizeof(void *)
    if (alignment &&
        ((alignment & (alignment - 1)) || (alignment % sizeof(void *)))) {
        LOG_ERR("wrong alignment: %zu (not a power of 2 or a multiple of "
                "sizeof(void *))",
                alignment);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    devdax_memory_provider_t *devdax_provider =
        (devdax_memory_provider_t *)provider;

    void *addr = NULL;
    errno = 0;
    ret = devdax_alloc_aligned(size, alignment, devdax_provider->base,
                               devdax_provider->size, &devdax_provider->lock,
                               &addr, &devdax_provider->offset);
    if (ret) {
        devdax_store_last_native_error(UMF_DEVDAX_RESULT_ERROR_ALLOC_FAILED, 0);
        LOG_ERR("memory allocation failed");
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    *resultPtr = addr;

    return UMF_RESULT_SUCCESS;
}

// free() is not supported
static umf_result_t devdax_free(void *provider, void *ptr, size_t size) {
    (void)provider; // unused
    (void)ptr;      // unused
    (void)size;     // unused

    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

static void devdax_get_last_native_error(void *provider, const char **ppMessage,
                                         int32_t *pError) {
    (void)provider; // unused

    if (ppMessage == NULL || pError == NULL) {
        assert(0);
        return;
    }

    *pError = TLS_last_native_error.native_error;
    if (TLS_last_native_error.errno_value == 0) {
        *ppMessage = Native_error_str[*pError - UMF_DEVDAX_RESULT_SUCCESS];
        return;
    }

    const char *msg;
    size_t len;
    size_t pos = 0;

    msg = Native_error_str[*pError - UMF_DEVDAX_RESULT_SUCCESS];
    len = strlen(msg);
    memcpy(TLS_last_native_error.msg_buff + pos, msg, len + 1);
    pos += len;

    msg = ": ";
    len = strlen(msg);
    memcpy(TLS_last_native_error.msg_buff + pos, msg, len + 1);
    pos += len;

    os_strerror(TLS_last_native_error.errno_value,
                TLS_last_native_error.msg_buff + pos, TLS_MSG_BUF_LEN - pos);

    *ppMessage = TLS_last_native_error.msg_buff;
}

static umf_result_t devdax_get_recommended_page_size(void *provider,
                                                     size_t size,
                                                     size_t *page_size) {
    (void)size; // unused

    if (provider == NULL || page_size == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *page_size = os_get_page_size();

    return UMF_RESULT_SUCCESS;
}

static umf_result_t devdax_get_min_page_size(void *provider, void *ptr,
                                             size_t *page_size) {
    (void)ptr; // unused

    return devdax_get_recommended_page_size(provider, 0, page_size);
}

static umf_result_t devdax_purge_lazy(void *provider, void *ptr, size_t size) {
    (void)provider; // unused
    (void)ptr;      // unused
    (void)size;     // unused
    // purge_lazy is unsupported in case of the devdax memory provider,
    // because the MADV_FREE operation can be applied
    // only to private anonymous pages (see madvise(2)).
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

static umf_result_t devdax_purge_force(void *provider, void *ptr, size_t size) {
    if (provider == NULL || ptr == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    errno = 0;
    if (os_purge(ptr, size, UMF_PURGE_FORCE)) {
        devdax_store_last_native_error(
            UMF_DEVDAX_RESULT_ERROR_PURGE_FORCE_FAILED, errno);
        LOG_PERR("force purging failed");
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }
    return UMF_RESULT_SUCCESS;
}

static const char *devdax_get_name(void *provider) {
    (void)provider; // unused
    return "DEVDAX";
}

static umf_result_t devdax_allocation_split(void *provider, void *ptr,
                                            size_t totalSize,
                                            size_t firstSize) {
    (void)provider;
    (void)ptr;
    (void)totalSize;
    (void)firstSize;

    return UMF_RESULT_SUCCESS;
}

static umf_result_t devdax_allocation_merge(void *provider, void *lowPtr,
                                            void *highPtr, size_t totalSize) {
    (void)provider;

    if ((uintptr_t)highPtr <= (uintptr_t)lowPtr) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if ((uintptr_t)highPtr - (uintptr_t)lowPtr <= totalSize) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    return UMF_RESULT_SUCCESS;
}

typedef struct devdax_ipc_data_t {
    char dd_path[PATH_MAX]; // path to the /dev/dax
    size_t dd_size;         // size of the /dev/dax
    size_t offset;          // offset of the data
} devdax_ipc_data_t;

static umf_result_t devdax_get_ipc_handle_size(void *provider, size_t *size) {
    if (provider == NULL || size == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *size = sizeof(devdax_ipc_data_t);

    return UMF_RESULT_SUCCESS;
}

static umf_result_t devdax_get_ipc_handle(void *provider, const void *ptr,
                                          size_t size, void *providerIpcData) {
    (void)size; // unused

    if (provider == NULL || ptr == NULL || providerIpcData == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    devdax_memory_provider_t *devdax_provider =
        (devdax_memory_provider_t *)provider;

    devdax_ipc_data_t *devdax_ipc_data = (devdax_ipc_data_t *)providerIpcData;
    devdax_ipc_data->offset =
        (size_t)((uintptr_t)ptr - (uintptr_t)devdax_provider->base);
    strncpy(devdax_ipc_data->dd_path, devdax_provider->path, PATH_MAX - 1);
    devdax_ipc_data->dd_path[PATH_MAX - 1] = '\0';
    devdax_ipc_data->dd_size = devdax_provider->size;

    return UMF_RESULT_SUCCESS;
}

static umf_result_t devdax_put_ipc_handle(void *provider,
                                          void *providerIpcData) {
    if (provider == NULL || providerIpcData == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    devdax_memory_provider_t *devdax_provider =
        (devdax_memory_provider_t *)provider;
    devdax_ipc_data_t *devdax_ipc_data = (devdax_ipc_data_t *)providerIpcData;

    // verify the path of the /dev/dax
    if (strncmp(devdax_ipc_data->dd_path, devdax_provider->path, PATH_MAX)) {
        LOG_ERR("devdax path mismatch (local: %s, ipc: %s)",
                devdax_provider->path, devdax_ipc_data->dd_path);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    // verify the size of the /dev/dax
    if (devdax_ipc_data->dd_size != devdax_provider->size) {
        LOG_ERR("devdax size mismatch (local: %zu, ipc: %zu)",
                devdax_provider->size, devdax_ipc_data->dd_size);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    return UMF_RESULT_SUCCESS;
}

static umf_result_t devdax_open_ipc_handle(void *provider,
                                           void *providerIpcData, void **ptr) {
    if (provider == NULL || providerIpcData == NULL || ptr == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    devdax_memory_provider_t *devdax_provider =
        (devdax_memory_provider_t *)provider;
    devdax_ipc_data_t *devdax_ipc_data = (devdax_ipc_data_t *)providerIpcData;

    // verify it is the same devdax - first verify the path
    if (strncmp(devdax_ipc_data->dd_path, devdax_provider->path, PATH_MAX)) {
        LOG_ERR("devdax path mismatch (local: %s, ipc: %s)",
                devdax_provider->path, devdax_ipc_data->dd_path);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    // verify the size of the /dev/dax
    if (devdax_ipc_data->dd_size != devdax_provider->size) {
        LOG_ERR("devdax size mismatch (local: %zu, ipc: %zu)",
                devdax_provider->size, devdax_ipc_data->dd_size);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_result_t ret = UMF_RESULT_SUCCESS;
    int fd = os_devdax_open(devdax_provider->path);
    if (fd <= 0) {
        LOG_PERR("opening a devdax (%s) failed", devdax_provider->path);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    char *base = os_devdax_mmap(NULL, devdax_provider->size,
                                devdax_provider->protection, fd);
    if (base == NULL) {
        devdax_store_last_native_error(UMF_DEVDAX_RESULT_ERROR_ALLOC_FAILED,
                                       errno);
        LOG_PERR("devdax mapping failed (path: %s, size: %zu, protection: %i, "
                 "fd: %i)",
                 devdax_provider->path, devdax_provider->size,
                 devdax_provider->protection, fd);
        ret = UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    LOG_DEBUG("devdax mapped (path: %s, size: %zu, protection: %i, fd: %i, "
              "offset: %zu)",
              devdax_provider->path, devdax_provider->size,
              devdax_provider->protection, fd, devdax_ipc_data->offset);

    (void)utils_close_fd(fd);

    *ptr = base + devdax_ipc_data->offset;

    return ret;
}

static umf_result_t devdax_close_ipc_handle(void *provider, void *ptr,
                                            size_t size) {
    if (provider == NULL || ptr == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    devdax_memory_provider_t *devdax_provider =
        (devdax_memory_provider_t *)provider;

    errno = 0;
    int ret = os_munmap(devdax_provider->base, devdax_provider->size);
    // ignore error when size == 0
    if (ret && (size > 0)) {
        devdax_store_last_native_error(UMF_DEVDAX_RESULT_ERROR_FREE_FAILED,
                                       errno);
        LOG_PERR("memory unmapping failed");

        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    return UMF_RESULT_SUCCESS;
}

static umf_memory_provider_ops_t UMF_DEVDAX_MEMORY_PROVIDER_OPS = {
    .version = UMF_VERSION_CURRENT,
    .initialize = devdax_initialize,
    .finalize = devdax_finalize,
    .alloc = devdax_alloc,
    .free = devdax_free,
    .get_last_native_error = devdax_get_last_native_error,
    .get_recommended_page_size = devdax_get_recommended_page_size,
    .get_min_page_size = devdax_get_min_page_size,
    .get_name = devdax_get_name,
    .ext.purge_lazy = devdax_purge_lazy,
    .ext.purge_force = devdax_purge_force,
    .ext.allocation_merge = devdax_allocation_merge,
    .ext.allocation_split = devdax_allocation_split,
    .ipc.get_ipc_handle_size = devdax_get_ipc_handle_size,
    .ipc.get_ipc_handle = devdax_get_ipc_handle,
    .ipc.put_ipc_handle = devdax_put_ipc_handle,
    .ipc.open_ipc_handle = devdax_open_ipc_handle,
    .ipc.close_ipc_handle = devdax_close_ipc_handle};

umf_memory_provider_ops_t *umfDevDaxMemoryProviderOps(void) {
    return &UMF_DEVDAX_MEMORY_PROVIDER_OPS;
}
