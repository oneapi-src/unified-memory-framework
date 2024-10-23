/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <umf.h>
#include <umf/memory_provider_ops.h>
#include <umf/providers/provider_file_memory.h>

#if defined(_WIN32) || defined(UMF_NO_HWLOC)

umf_memory_provider_ops_t *umfFileMemoryProviderOps(void) {
    // not supported
    return NULL;
}

#else // !defined(_WIN32) && !defined(UMF_NO_HWLOC)

#include "base_alloc_global.h"
#include "critnib.h"
#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_log.h"

#define TLS_MSG_BUF_LEN 1024

typedef struct file_memory_provider_t {
    utils_mutex_t lock; // lock for file parameters (size and offsets)

    char path[PATH_MAX]; // a path to the file
    int fd;              // file descriptor for memory mapping
    size_t size_fd;      // size of the file used for memory mappings
    size_t offset_fd;    // offset in the file used for memory mappings

    void *base_mmap;    // base address of the current memory mapping
    size_t size_mmap;   // size of the current memory mapping
    size_t offset_mmap; // data offset in the current memory mapping

    unsigned protection; // combination of OS-specific protection flags
    unsigned visibility; // memory visibility mode
    size_t page_size;    // minimum page size

    // IPC is enabled only for UMF_MEM_MAP_SHARED or UMF_MEM_MAP_SYNC visibility
    bool IPC_enabled;

    critnib *mmaps; // a critnib map storing mmap mappings (addr, size)

    // A critnib map storing (ptr, fd_offset + 1) pairs. We add 1 to fd_offset
    // in order to be able to store fd_offset equal 0, because
    // critnib_get() returns value or NULL, so a value cannot equal 0.
    // It is needed mainly in the get_ipc_handle and open_ipc_handle hooks
    // to mmap a specific part of a file.
    critnib *fd_offset_map;
} file_memory_provider_t;

typedef struct file_last_native_error_t {
    int32_t native_error;
    int errno_value;
    char msg_buff[TLS_MSG_BUF_LEN];
} file_last_native_error_t;

static __TLS file_last_native_error_t TLS_last_native_error;

// helper values used only in the Native_error_str array
#define _UMF_FILE_RESULT_SUCCESS                                               \
    (UMF_FILE_RESULT_SUCCESS - UMF_FILE_RESULT_SUCCESS)
#define _UMF_FILE_RESULT_ERROR_ALLOC_FAILED                                    \
    (UMF_FILE_RESULT_ERROR_ALLOC_FAILED - UMF_FILE_RESULT_SUCCESS)
#define _UMF_FILE_RESULT_ERROR_FREE_FAILED                                     \
    (UMF_FILE_RESULT_ERROR_FREE_FAILED - UMF_FILE_RESULT_SUCCESS)
#define _UMF_FILE_RESULT_ERROR_PURGE_FORCE_FAILED                              \
    (UMF_FILE_RESULT_ERROR_PURGE_FORCE_FAILED - UMF_FILE_RESULT_SUCCESS)

static const char *Native_error_str[] = {
    [_UMF_FILE_RESULT_SUCCESS] = "success",
    [_UMF_FILE_RESULT_ERROR_ALLOC_FAILED] = "memory allocation failed",
    [_UMF_FILE_RESULT_ERROR_FREE_FAILED] = "memory deallocation failed",
    [_UMF_FILE_RESULT_ERROR_PURGE_FORCE_FAILED] = "force purging failed",
};

static void file_store_last_native_error(int32_t native_error,
                                         int errno_value) {
    TLS_last_native_error.native_error = native_error;
    TLS_last_native_error.errno_value = errno_value;
}

static umf_result_t
file_translate_params(umf_file_memory_provider_params_t *in_params,
                      file_memory_provider_t *provider) {
    umf_result_t result;

    result = utils_translate_mem_protection_flags(in_params->protection,
                                                  &provider->protection);
    if (result != UMF_RESULT_SUCCESS) {
        LOG_ERR("incorrect memory protection flags: %u", in_params->protection);
        return result;
    }

    result = utils_translate_mem_visibility_flag(in_params->visibility,
                                                 &provider->visibility);
    if (result != UMF_RESULT_SUCCESS) {
        LOG_ERR("incorrect memory visibility flag: %u", in_params->visibility);
        return result;
    }

    // IPC is enabled only for UMF_MEM_MAP_SHARED or UMF_MEM_MAP_SYNC visibility
    provider->IPC_enabled = (in_params->visibility == UMF_MEM_MAP_SHARED ||
                             in_params->visibility == UMF_MEM_MAP_SYNC);

    return UMF_RESULT_SUCCESS;
}

static umf_result_t file_initialize(void *params, void **provider) {
    umf_result_t ret;

    if (provider == NULL || params == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_file_memory_provider_params_t *in_params =
        (umf_file_memory_provider_params_t *)params;

    size_t page_size = utils_get_page_size();

    if (in_params->path == NULL) {
        LOG_ERR("file path is missing");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    file_memory_provider_t *file_provider =
        umf_ba_global_alloc(sizeof(*file_provider));
    if (!file_provider) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    memset(file_provider, 0, sizeof(*file_provider));

    file_provider->page_size = page_size;

    ret = file_translate_params(in_params, file_provider);
    if (ret != UMF_RESULT_SUCCESS) {
        goto err_free_file_provider;
    }

    if (utils_copy_path(in_params->path, file_provider->path, PATH_MAX)) {
        goto err_free_file_provider;
    }

    file_provider->fd = utils_file_open_or_create(in_params->path);
    if (file_provider->fd == -1) {
        LOG_ERR("cannot open the file: %s", in_params->path);
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err_free_file_provider;
    }

    if (utils_set_file_size(file_provider->fd, page_size)) {
        LOG_ERR("cannot set size of the file: %s", in_params->path);
        ret = UMF_RESULT_ERROR_UNKNOWN;
        goto err_close_fd;
    }

    file_provider->size_fd = page_size;

    LOG_DEBUG("size of the file %s is: %zu", in_params->path,
              file_provider->size_fd);

    if (utils_mutex_init(&file_provider->lock) == NULL) {
        LOG_ERR("lock init failed");
        ret = UMF_RESULT_ERROR_UNKNOWN;
        goto err_close_fd;
    }

    file_provider->fd_offset_map = critnib_new();
    if (!file_provider->fd_offset_map) {
        LOG_ERR("creating the map of file descriptor offsets failed");
        ret = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        goto err_mutex_destroy_not_free;
    }

    file_provider->mmaps = critnib_new();
    if (!file_provider->mmaps) {
        LOG_ERR("creating the map of memory mappings failed");
        ret = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        goto err_delete_fd_offset_map;
    }

    *provider = file_provider;

    return UMF_RESULT_SUCCESS;

err_delete_fd_offset_map:
    critnib_delete(file_provider->fd_offset_map);
err_mutex_destroy_not_free:
    utils_mutex_destroy_not_free(&file_provider->lock);
err_close_fd:
    utils_close_fd(file_provider->fd);
err_free_file_provider:
    umf_ba_global_free(file_provider);
    return ret;
}

static void file_finalize(void *provider) {
    if (provider == NULL) {
        assert(0);
        return;
    }

    file_memory_provider_t *file_provider = provider;

    uintptr_t key = 0;
    uintptr_t rkey = 0;
    void *rvalue = NULL;
    while (1 ==
           critnib_find(file_provider->mmaps, key, FIND_G, &rkey, &rvalue)) {
        utils_munmap((void *)rkey, (size_t)rvalue);
        critnib_remove(file_provider->mmaps, rkey);
        key = rkey;
    }

    utils_mutex_destroy_not_free(&file_provider->lock);
    utils_close_fd(file_provider->fd);
    critnib_delete(file_provider->fd_offset_map);
    critnib_delete(file_provider->mmaps);
    umf_ba_global_free(file_provider);
}

static umf_result_t file_mmap_aligned(file_memory_provider_t *file_provider,
                                      size_t size, size_t alignment) {
    int prot = file_provider->protection;
    int flag = file_provider->visibility;
    int fd = file_provider->fd;
    size_t size_fd = file_provider->size_fd;
    size_t offset_fd = file_provider->offset_fd;
    size_t page_size = file_provider->page_size;

    assert(fd > 0);

    // We have to increase size by alignment to be able to "cut out"
    // the correctly aligned part of the memory
    size_t extended_size = size + alignment;
    if (extended_size < size) {
        LOG_ERR("invalid size of allocation");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT; // arithmetic overflow
    }

    size_t rest = extended_size & (page_size - 1);
    if (rest) {
        extended_size += page_size - rest;
    }
    if (extended_size < size) {
        LOG_ERR("invalid size of allocation");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT; // arithmetic overflow
    }

    // offset_fd has to be also page-aligned since it is the offset of mmap()
    size_t aligned_offset_fd = offset_fd;
    rest = aligned_offset_fd & (page_size - 1);
    if (rest) {
        aligned_offset_fd += page_size - rest;
    }
    if (aligned_offset_fd < offset_fd) {
        LOG_ERR("arithmetic overflow of file offset");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT; // arithmetic overflow
    }

    if (aligned_offset_fd + extended_size > size_fd) {
        size_t new_size_fd = aligned_offset_fd + extended_size;
        if (utils_fallocate(fd, size_fd, new_size_fd - size_fd)) {
            LOG_ERR("cannot grow the file size from %zu to %zu", size_fd,
                    new_size_fd);
            return UMF_RESULT_ERROR_UNKNOWN;
        }

        LOG_DEBUG("file size grown from %zu to %zu", size_fd, new_size_fd);
        file_provider->size_fd = new_size_fd;
    }

    if (aligned_offset_fd > offset_fd) {
        file_provider->offset_fd = aligned_offset_fd;
    }

    ASSERT_IS_ALIGNED(extended_size, page_size);
    ASSERT_IS_ALIGNED(aligned_offset_fd, page_size);

    void *ptr =
        utils_mmap_file(NULL, extended_size, prot, flag, fd, aligned_offset_fd);
    if (ptr == NULL) {
        LOG_PERR("memory mapping failed");
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    int ret = critnib_insert(file_provider->mmaps, (uintptr_t)ptr,
                             (void *)(uintptr_t)extended_size, 0 /* update */);
    if (ret) {
        LOG_ERR("inserting a value to the map of memory mapping failed "
                "(addr=%p, size=%zu)",
                ptr, extended_size);
    }

    LOG_DEBUG(
        "inserted a value to the map of memory mapping (addr=%p, size=%zu)",
        ptr, extended_size);

    file_provider->base_mmap = ptr;
    file_provider->size_mmap = extended_size;
    file_provider->offset_mmap = 0;

    return UMF_RESULT_SUCCESS;
}

static umf_result_t file_alloc_aligned(file_memory_provider_t *file_provider,
                                       size_t size, size_t alignment,
                                       void **out_addr,
                                       size_t *alloc_offset_fd) {
    assert(alloc_offset_fd);
    assert(out_addr);

    umf_result_t umf_result;

    if (utils_mutex_lock(&file_provider->lock)) {
        LOG_ERR("locking file data failed");
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    if (file_provider->size_mmap - file_provider->offset_mmap < size) {
        umf_result = file_mmap_aligned(file_provider, size, alignment);
        if (umf_result != UMF_RESULT_SUCCESS) {
            utils_mutex_unlock(&file_provider->lock);
            return umf_result;
        }
    }

    void *base_mmap = file_provider->base_mmap;
    assert(base_mmap);

    uintptr_t new_aligned_ptr =
        (uintptr_t)base_mmap + file_provider->offset_mmap;
    if (alignment) {
        uintptr_t rest = new_aligned_ptr & (alignment - 1);
        if (rest) {
            new_aligned_ptr += alignment - rest;
        }
        ASSERT_IS_ALIGNED(new_aligned_ptr, alignment);
    }

    size_t new_offset_mmap = new_aligned_ptr - (uintptr_t)base_mmap;
    size_t new_offset_fd =
        file_provider->offset_fd + new_offset_mmap - file_provider->offset_mmap;

    if (file_provider->size_mmap - new_offset_mmap < size) {
        umf_result = file_mmap_aligned(file_provider, size, alignment);
        if (umf_result != UMF_RESULT_SUCCESS) {
            utils_mutex_unlock(&file_provider->lock);
            return umf_result;
        }

        assert(file_provider->base_mmap);

        // file_provider-> base_mmap, offset_mmap, offset_fd
        // were updated by file_mmap_aligned():
        new_aligned_ptr = (uintptr_t)file_provider->base_mmap;
        new_offset_mmap = 0; // == file_provider->offset_mmap
        new_offset_fd = file_provider->offset_fd;

        ASSERT_IS_ALIGNED(new_aligned_ptr, alignment);
    }

    *alloc_offset_fd = new_offset_fd;

    file_provider->offset_fd = new_offset_fd + size;
    file_provider->offset_mmap = new_offset_mmap + size;

    *out_addr = (void *)new_aligned_ptr;

    utils_mutex_unlock(&file_provider->lock);

    return UMF_RESULT_SUCCESS;
}

static umf_result_t file_alloc(void *provider, size_t size, size_t alignment,
                               void **resultPtr) {
    umf_result_t umf_result;
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
        return UMF_RESULT_ERROR_INVALID_ALIGNMENT;
    }

    file_memory_provider_t *file_provider = (file_memory_provider_t *)provider;

    void *addr = NULL;
    size_t alloc_offset_fd; // needed for critnib_insert()
    umf_result = file_alloc_aligned(file_provider, size, alignment, &addr,
                                    &alloc_offset_fd);
    if (umf_result != UMF_RESULT_SUCCESS) {
        file_store_last_native_error(UMF_FILE_RESULT_ERROR_ALLOC_FAILED, 0);
        LOG_ERR("memory allocation failed");
        return umf_result;
    }

    // store (offset_fd + 1) to be able to store offset_fd == 0
    ret = critnib_insert(file_provider->fd_offset_map, (uintptr_t)addr,
                         (void *)(uintptr_t)(alloc_offset_fd + 1),
                         0 /* update */);
    if (ret) {
        LOG_ERR("inserting a value to the file descriptor offset map failed "
                "(addr=%p, offset=%zu)",
                addr, alloc_offset_fd);
    }

    *resultPtr = addr;

    return UMF_RESULT_SUCCESS;
}

static void file_get_last_native_error(void *provider, const char **ppMessage,
                                       int32_t *pError) {
    (void)provider; // unused

    if (ppMessage == NULL || pError == NULL) {
        assert(0);
        return;
    }

    *pError = TLS_last_native_error.native_error;
    if (TLS_last_native_error.errno_value == 0) {
        *ppMessage = Native_error_str[*pError - UMF_FILE_RESULT_SUCCESS];
        return;
    }

    const char *msg;
    size_t len;
    size_t pos = 0;

    msg = Native_error_str[*pError - UMF_FILE_RESULT_SUCCESS];
    len = strlen(msg);
    memcpy(TLS_last_native_error.msg_buff + pos, msg, len + 1);
    pos += len;

    msg = ": ";
    len = strlen(msg);
    memcpy(TLS_last_native_error.msg_buff + pos, msg, len + 1);
    pos += len;

    utils_strerror(TLS_last_native_error.errno_value,
                   TLS_last_native_error.msg_buff + pos, TLS_MSG_BUF_LEN - pos);

    *ppMessage = TLS_last_native_error.msg_buff;
}

static umf_result_t file_get_recommended_page_size(void *provider, size_t size,
                                                   size_t *page_size) {
    (void)size; // unused

    if (provider == NULL || page_size == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *page_size = utils_get_page_size();

    return UMF_RESULT_SUCCESS;
}

static umf_result_t file_get_min_page_size(void *provider, void *ptr,
                                           size_t *page_size) {
    (void)ptr; // unused

    return file_get_recommended_page_size(provider, 0, page_size);
}

static umf_result_t file_purge_lazy(void *provider, void *ptr, size_t size) {
    (void)provider; // unused
    (void)ptr;      // unused
    (void)size;     // unused
    // purge_lazy is unsupported in case of the file memory provider,
    // because the MADV_FREE operation can be applied
    // only to private anonymous pages (see madvise(2)).
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

static umf_result_t file_purge_force(void *provider, void *ptr, size_t size) {
    if (provider == NULL || ptr == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    errno = 0;
    if (utils_purge(ptr, size, UMF_PURGE_FORCE)) {
        file_store_last_native_error(UMF_FILE_RESULT_ERROR_PURGE_FORCE_FAILED,
                                     errno);
        LOG_PERR("force purging failed");
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }
    return UMF_RESULT_SUCCESS;
}

static const char *file_get_name(void *provider) {
    (void)provider; // unused
    return "FILE";
}

// This function is supposed to be thread-safe, so it should NOT be called concurrently
// with file_allocation_merge() with the same pointer.
static umf_result_t file_allocation_split(void *provider, void *ptr,
                                          size_t totalSize, size_t firstSize) {
    (void)totalSize;

    file_memory_provider_t *file_provider = (file_memory_provider_t *)provider;
    if (file_provider->fd <= 0) {
        return UMF_RESULT_SUCCESS;
    }

    void *value = critnib_get(file_provider->fd_offset_map, (uintptr_t)ptr);
    if (value == NULL) {
        LOG_ERR("file_allocation_split(): getting a value from the file "
                "descriptor offset map failed (addr=%p)",
                ptr);
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    uintptr_t new_key = (uintptr_t)ptr + firstSize;
    void *new_value = (void *)((uintptr_t)value + firstSize);
    int ret = critnib_insert(file_provider->fd_offset_map, new_key, new_value,
                             0 /* update */);
    if (ret) {
        LOG_ERR("file_allocation_split(): inserting a value to the file "
                "descriptor offset map failed (addr=%p, offset=%zu)",
                (void *)new_key, (size_t)new_value - 1);
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    return UMF_RESULT_SUCCESS;
}

// It should NOT be called concurrently with file_allocation_split() with the same pointer.
static umf_result_t file_allocation_merge(void *provider, void *lowPtr,
                                          void *highPtr, size_t totalSize) {
    (void)lowPtr;
    (void)totalSize;

    file_memory_provider_t *file_provider = (file_memory_provider_t *)provider;
    if (file_provider->fd <= 0) {
        return UMF_RESULT_SUCCESS;
    }

    void *value =
        critnib_remove(file_provider->fd_offset_map, (uintptr_t)highPtr);
    if (value == NULL) {
        LOG_ERR("file_allocation_merge(): removing a value from the file "
                "descriptor offset map failed (addr=%p)",
                highPtr);
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    return UMF_RESULT_SUCCESS;
}

typedef struct file_ipc_data_t {
    char path[PATH_MAX];
    size_t offset_fd;
    size_t size;
} file_ipc_data_t;

static umf_result_t file_get_ipc_handle_size(void *provider, size_t *size) {
    if (provider == NULL || size == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    file_memory_provider_t *file_provider = (file_memory_provider_t *)provider;
    if (!file_provider->IPC_enabled) {
        LOG_ERR("memory visibility mode is not UMF_MEM_MAP_SHARED nor "
                "UMF_MEM_MAP_SYNC")
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *size = sizeof(file_ipc_data_t);

    return UMF_RESULT_SUCCESS;
}

static umf_result_t file_get_ipc_handle(void *provider, const void *ptr,
                                        size_t size, void *providerIpcData) {
    if (provider == NULL || ptr == NULL || providerIpcData == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    file_memory_provider_t *file_provider = (file_memory_provider_t *)provider;
    if (!file_provider->IPC_enabled) {
        LOG_ERR("memory visibility mode is not UMF_MEM_MAP_SHARED nor "
                "UMF_MEM_MAP_SYNC")
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    void *value = critnib_get(file_provider->fd_offset_map, (uintptr_t)ptr);
    if (value == NULL) {
        LOG_ERR("file_get_ipc_handle(): getting a value from the IPC cache "
                "failed (addr=%p)",
                ptr);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    file_ipc_data_t *file_ipc_data = (file_ipc_data_t *)providerIpcData;
    file_ipc_data->offset_fd = (size_t)value - 1;
    file_ipc_data->size = size;
    strncpy(file_ipc_data->path, file_provider->path, PATH_MAX - 1);
    file_ipc_data->path[PATH_MAX - 1] = '\0';

    return UMF_RESULT_SUCCESS;
}

static umf_result_t file_put_ipc_handle(void *provider, void *providerIpcData) {
    if (provider == NULL || providerIpcData == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    file_memory_provider_t *file_provider = (file_memory_provider_t *)provider;
    if (!file_provider->IPC_enabled) {
        LOG_ERR("memory visibility mode is not UMF_MEM_MAP_SHARED nor "
                "UMF_MEM_MAP_SYNC")
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    file_ipc_data_t *file_ipc_data = (file_ipc_data_t *)providerIpcData;

    if (strncmp(file_ipc_data->path, file_provider->path, PATH_MAX)) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    return UMF_RESULT_SUCCESS;
}

static umf_result_t file_open_ipc_handle(void *provider, void *providerIpcData,
                                         void **ptr) {
    if (provider == NULL || providerIpcData == NULL || ptr == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    file_memory_provider_t *file_provider = (file_memory_provider_t *)provider;
    if (!file_provider->IPC_enabled) {
        LOG_ERR("memory visibility mode is not UMF_MEM_MAP_SHARED nor "
                "UMF_MEM_MAP_SYNC")
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    file_ipc_data_t *file_ipc_data = (file_ipc_data_t *)providerIpcData;
    umf_result_t ret = UMF_RESULT_SUCCESS;
    int fd;

    fd = utils_file_open(file_ipc_data->path);
    if (fd == -1) {
        LOG_PERR("opening the file to be mapped (%s) failed",
                 file_ipc_data->path);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *ptr = utils_mmap_file(NULL, file_ipc_data->size, file_provider->protection,
                           file_provider->visibility, fd,
                           file_ipc_data->offset_fd);
    (void)utils_close_fd(fd);
    if (*ptr == NULL) {
        file_store_last_native_error(UMF_FILE_RESULT_ERROR_ALLOC_FAILED, errno);
        LOG_PERR("memory mapping failed");
        ret = UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    return ret;
}

static umf_result_t file_close_ipc_handle(void *provider, void *ptr,
                                          size_t size) {
    if (provider == NULL || ptr == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    file_memory_provider_t *file_provider = (file_memory_provider_t *)provider;
    if (!file_provider->IPC_enabled) {
        LOG_ERR("memory visibility mode is not UMF_MEM_MAP_SHARED nor "
                "UMF_MEM_MAP_SYNC")
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    errno = 0;
    int ret = utils_munmap(ptr, size);
    // ignore error when size == 0
    if (ret && (size > 0)) {
        file_store_last_native_error(UMF_FILE_RESULT_ERROR_FREE_FAILED, errno);
        LOG_PERR("memory unmapping failed");

        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    return UMF_RESULT_SUCCESS;
}

static umf_memory_provider_ops_t UMF_FILE_MEMORY_PROVIDER_OPS = {
    .version = UMF_VERSION_CURRENT,
    .initialize = file_initialize,
    .finalize = file_finalize,
    .alloc = file_alloc,
    .get_last_native_error = file_get_last_native_error,
    .get_recommended_page_size = file_get_recommended_page_size,
    .get_min_page_size = file_get_min_page_size,
    .get_name = file_get_name,
    .ext.purge_lazy = file_purge_lazy,
    .ext.purge_force = file_purge_force,
    .ext.allocation_merge = file_allocation_merge,
    .ext.allocation_split = file_allocation_split,
    .ipc.get_ipc_handle_size = file_get_ipc_handle_size,
    .ipc.get_ipc_handle = file_get_ipc_handle,
    .ipc.put_ipc_handle = file_put_ipc_handle,
    .ipc.open_ipc_handle = file_open_ipc_handle,
    .ipc.close_ipc_handle = file_close_ipc_handle};

umf_memory_provider_ops_t *umfFileMemoryProviderOps(void) {
    return &UMF_FILE_MEMORY_PROVIDER_OPS;
}

#endif // !defined(_WIN32) && !defined(UMF_NO_HWLOC)
