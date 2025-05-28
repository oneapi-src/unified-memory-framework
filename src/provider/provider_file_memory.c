/*
 * Copyright (C) 2024-2025 Intel Corporation
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

#include "utils_log.h"

#if defined(_WIN32) || defined(UMF_NO_HWLOC)

const umf_memory_provider_ops_t *umfFileMemoryProviderOps(void) {
    // not supported
    LOG_ERR("File memory provider is disabled!");
    return NULL;
}

umf_result_t umfFileMemoryProviderParamsCreate(
    umf_file_memory_provider_params_handle_t *hParams, const char *path) {
    (void)hParams;
    (void)path;
    LOG_ERR("File memory provider is disabled!");
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

umf_result_t umfFileMemoryProviderParamsDestroy(
    umf_file_memory_provider_params_handle_t hParams) {
    (void)hParams;
    LOG_ERR("File memory provider is disabled!");
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

umf_result_t umfFileMemoryProviderParamsSetPath(
    umf_file_memory_provider_params_handle_t hParams, const char *path) {
    (void)hParams;
    (void)path;
    LOG_ERR("File memory provider is disabled!");
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

umf_result_t umfFileMemoryProviderParamsSetProtection(
    umf_file_memory_provider_params_handle_t hParams, unsigned protection) {
    (void)hParams;
    (void)protection;
    LOG_ERR("File memory provider is disabled!");
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

umf_result_t umfFileMemoryProviderParamsSetVisibility(
    umf_file_memory_provider_params_handle_t hParams,
    umf_memory_visibility_t visibility) {
    (void)hParams;
    (void)visibility;
    LOG_ERR("File memory provider is disabled!");
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

#else // !defined(_WIN32) && !defined(UMF_NO_HWLOC)

#include "base_alloc_global.h"
#include "coarse.h"
#include "critnib.h"
#include "libumf.h"
#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_log.h"

#define FSDAX_PAGE_SIZE_2MB ((size_t)(2 * 1024 * 1024)) // == 2 MB

#define TLS_MSG_BUF_LEN 1024

typedef struct file_memory_provider_t {
    utils_mutex_t lock; // lock for file parameters (size and offsets)

    char path[PATH_MAX]; // a path to the file
    bool is_fsdax;       // true if file is located on FSDAX
    int fd;              // file descriptor for memory mapping
    size_t size_fd;      // size of the file used for memory mappings
    size_t offset_fd;    // offset in the file used for memory mappings

    void *base_mmap;    // base address of the current memory mapping
    size_t size_mmap;   // size of the current memory mapping
    size_t offset_mmap; // data offset in the current memory mapping

    unsigned protection; // combination of OS-specific protection flags
    unsigned visibility; // memory visibility mode
    size_t page_size;    // minimum page size

    // IPC is enabled only for the UMF_MEM_MAP_SHARED visibility
    bool IPC_enabled;

    critnib *mmaps; // a critnib map storing mmap mappings (addr, size)

    // A critnib map storing (ptr, fd_offset + 1) pairs. We add 1 to fd_offset
    // in order to be able to store fd_offset equal 0, because
    // critnib_get() returns value or NULL, so a value cannot equal 0.
    // It is needed mainly in the ipc_get_handle and ipc_open_handle hooks
    // to mmap a specific part of a file.
    critnib *fd_offset_map;

    coarse_t *coarse; // coarse library handle
} file_memory_provider_t;

// File Memory Provider settings struct
typedef struct umf_file_memory_provider_params_t {
    char *path;
    unsigned protection;
    umf_memory_visibility_t visibility;
} umf_file_memory_provider_params_t;

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
file_translate_params(const umf_file_memory_provider_params_t *in_params,
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

    // IPC is enabled only for the UMF_MEM_MAP_SHARED visibility
    provider->IPC_enabled = (in_params->visibility == UMF_MEM_MAP_SHARED);

    return UMF_RESULT_SUCCESS;
}

static umf_result_t file_alloc_cb(void *provider, size_t size, size_t alignment,
                                  void **resultPtr);
static umf_result_t file_allocation_split_cb(void *provider, void *ptr,
                                             size_t totalSize,
                                             size_t firstSize);
static umf_result_t file_allocation_merge_cb(void *provider, void *lowPtr,
                                             void *highPtr, size_t totalSize);

static umf_result_t file_initialize(const void *params, void **provider) {
    umf_result_t ret;

    if (params == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    const umf_file_memory_provider_params_t *in_params = params;

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

    if (utils_set_file_size(file_provider->fd, FSDAX_PAGE_SIZE_2MB)) {
        LOG_ERR("cannot set size of the file: %s", in_params->path);
        ret = UMF_RESULT_ERROR_UNKNOWN;
        goto err_close_fd;
    }

    file_provider->size_fd = FSDAX_PAGE_SIZE_2MB;

    LOG_DEBUG("size of the file %s is: %zu", in_params->path,
              file_provider->size_fd);

    if (!(in_params->visibility & UMF_MEM_MAP_PRIVATE)) {
        // check if file is located on FSDAX
        void *addr = utils_mmap_file(
            NULL, file_provider->size_fd, file_provider->protection,
            file_provider->visibility, file_provider->fd, 0,
            &file_provider->is_fsdax);
        if (addr) {
            utils_munmap(addr, file_provider->size_fd);
        }
    }

    if (file_provider->is_fsdax) {
        file_provider->page_size = FSDAX_PAGE_SIZE_2MB;
    } else {
        file_provider->page_size = utils_get_page_size();
    }

    coarse_params_t coarse_params = {0};
    coarse_params.provider = file_provider;
    coarse_params.page_size = file_provider->page_size;
    coarse_params.cb.alloc = file_alloc_cb;
    coarse_params.cb.free = NULL; // not available for the file provider
    coarse_params.cb.split = file_allocation_split_cb;
    coarse_params.cb.merge = file_allocation_merge_cb;

    coarse_t *coarse = NULL;
    ret = coarse_new(&coarse_params, &coarse);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("coarse_new() failed");
        goto err_close_fd;
    }

    file_provider->coarse = coarse;

    if (utils_mutex_init(&file_provider->lock) == NULL) {
        LOG_ERR("lock init failed");
        ret = UMF_RESULT_ERROR_UNKNOWN;
        goto err_coarse_delete;
    }

    file_provider->fd_offset_map = critnib_new(NULL, NULL);
    if (!file_provider->fd_offset_map) {
        LOG_ERR("creating the map of file descriptor offsets failed");
        ret = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        goto err_mutex_destroy_not_free;
    }

    file_provider->mmaps = critnib_new(NULL, NULL);
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
err_coarse_delete:
    coarse_delete(file_provider->coarse);
err_close_fd:
    utils_close_fd(file_provider->fd);
err_free_file_provider:
    umf_ba_global_free(file_provider);
    return ret;
}

static void file_finalize(void *provider) {
    file_memory_provider_t *file_provider = provider;

    uintptr_t key = 0;
    uintptr_t rkey = 0;
    void *rvalue = NULL;
    while (1 == critnib_find(file_provider->mmaps, key, FIND_G, &rkey, &rvalue,
                             NULL)) {
        utils_munmap((void *)rkey, (size_t)rvalue);
        critnib_remove(file_provider->mmaps, rkey, NULL);
        key = rkey;
    }

    utils_mutex_destroy_not_free(&file_provider->lock);
    utils_close_fd(file_provider->fd);
    critnib_delete(file_provider->fd_offset_map);
    critnib_delete(file_provider->mmaps);
    coarse_delete(file_provider->coarse);
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

    void *ptr = utils_mmap_file(NULL, extended_size, prot, flag, fd,
                                aligned_offset_fd, NULL);
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

    // align the new pointer
    uintptr_t aligned_ptr = ALIGN_UP_SAFE((uintptr_t)ptr, alignment);
    size_t aligned_size = extended_size - (aligned_ptr - (uintptr_t)ptr);

    file_provider->base_mmap = (void *)aligned_ptr;
    file_provider->size_mmap = aligned_size;
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

    assert(file_provider->offset_mmap <= file_provider->size_mmap);

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

    // new_offset_mmap can be greater than file_provider->size_mmap
    if (file_provider->size_mmap < size + new_offset_mmap) {
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
    file_memory_provider_t *file_provider = (file_memory_provider_t *)provider;
    return coarse_alloc(file_provider->coarse, size, alignment, resultPtr);
}

static umf_result_t file_alloc_cb(void *provider, size_t size, size_t alignment,
                                  void **resultPtr) {
    umf_result_t umf_result;
    int ret;

    file_memory_provider_t *file_provider = (file_memory_provider_t *)provider;

    *resultPtr = NULL;

    // alignment must be a power of two and a multiple or a divider of the page size
    if (alignment && ((alignment & (alignment - 1)) ||
                      ((alignment % file_provider->page_size) &&
                       (file_provider->page_size % alignment)))) {
        LOG_ERR("wrong alignment: %zu (not a power of 2 or a multiple or a "
                "divider of the page size (%zu))",
                alignment, file_provider->page_size);
        return UMF_RESULT_ERROR_INVALID_ALIGNMENT;
    }

    if (IS_NOT_ALIGNED(alignment, file_provider->page_size)) {
        alignment = ALIGN_UP(alignment, file_provider->page_size);
    }

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
        // We cannot undo the file_alloc_aligned() call here,
        // because the file memory provider does not support the free operation.
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    LOG_DEBUG("inserted a value to the file descriptor offset map (addr=%p, "
              "offset=%zu)",
              addr, alloc_offset_fd);

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
    (void)provider; // unused
    (void)size;     // unused

    file_memory_provider_t *file_provider = (file_memory_provider_t *)provider;
    *page_size = file_provider->page_size;

    return UMF_RESULT_SUCCESS;
}

static umf_result_t file_get_min_page_size(void *provider, const void *ptr,
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
    (void)provider; // unused

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

static umf_result_t file_allocation_split(void *provider, void *ptr,
                                          size_t totalSize, size_t firstSize) {
    file_memory_provider_t *file_provider = (file_memory_provider_t *)provider;
    return coarse_split(file_provider->coarse, ptr, totalSize, firstSize);
}

static umf_result_t file_allocation_split_cb(void *provider, void *ptr,
                                             size_t totalSize,
                                             size_t firstSize) {
    (void)totalSize;

    file_memory_provider_t *file_provider = (file_memory_provider_t *)provider;
    if (file_provider->fd <= 0) {
        return UMF_RESULT_SUCCESS;
    }

    void *value =
        critnib_get(file_provider->fd_offset_map, (uintptr_t)ptr, NULL);
    if (value == NULL) {
        LOG_ERR("getting a value from the file descriptor offset map failed "
                "(addr=%p)",
                ptr);
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    LOG_DEBUG("split the value from the file descriptor offset map (addr=%p) "
              "from size %zu to %zu + %zu",
              ptr, totalSize, firstSize, totalSize - firstSize);

    uintptr_t new_key = (uintptr_t)ptr + firstSize;
    void *new_value = (void *)((uintptr_t)value + firstSize);
    int ret = critnib_insert(file_provider->fd_offset_map, new_key, new_value,
                             0 /* update */);
    if (ret) {
        LOG_ERR("inserting a value to the file descriptor offset map failed "
                "(addr=%p, offset=%zu)",
                (void *)new_key, (size_t)new_value - 1);
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    LOG_DEBUG("inserted a value to the file descriptor offset map (addr=%p, "
              "offset=%zu)",
              (void *)new_key, (size_t)new_value - 1);

    return UMF_RESULT_SUCCESS;
}

static umf_result_t file_allocation_merge(void *provider, void *lowPtr,
                                          void *highPtr, size_t totalSize) {
    file_memory_provider_t *file_provider = (file_memory_provider_t *)provider;
    return coarse_merge(file_provider->coarse, lowPtr, highPtr, totalSize);
}

static umf_result_t file_allocation_merge_cb(void *provider, void *lowPtr,
                                             void *highPtr, size_t totalSize) {
    (void)lowPtr;
    (void)totalSize;

    file_memory_provider_t *file_provider = (file_memory_provider_t *)provider;
    if (file_provider->fd <= 0) {
        return UMF_RESULT_SUCCESS;
    }

    void *value =
        critnib_remove(file_provider->fd_offset_map, (uintptr_t)highPtr, NULL);
    if (value == NULL) {
        LOG_ERR("removing a value from the file descriptor offset map failed "
                "(addr=%p)",
                highPtr);
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    LOG_DEBUG("removed a value from the file descriptor offset map (addr=%p) - "
              "merged with %p",
              highPtr, lowPtr);

    return UMF_RESULT_SUCCESS;
}

typedef struct file_ipc_data_t {
    char path[PATH_MAX];
    size_t offset_fd;
    size_t size;
    unsigned protection; // combination of OS-specific protection flags
    unsigned visibility; // memory visibility mode
} file_ipc_data_t;

static umf_result_t file_get_ipc_handle_size(void *provider, size_t *size) {
    file_memory_provider_t *file_provider = (file_memory_provider_t *)provider;
    if (!file_provider->IPC_enabled) {
        LOG_ERR("memory visibility mode is not UMF_MEM_MAP_SHARED")
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *size = sizeof(file_ipc_data_t);

    return UMF_RESULT_SUCCESS;
}

static umf_result_t file_get_ipc_handle(void *provider, const void *ptr,
                                        size_t size, void *providerIpcData) {
    file_memory_provider_t *file_provider = (file_memory_provider_t *)provider;
    if (!file_provider->IPC_enabled) {
        LOG_ERR("memory visibility mode is not UMF_MEM_MAP_SHARED")
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    void *value =
        critnib_get(file_provider->fd_offset_map, (uintptr_t)ptr, NULL);
    if (value == NULL) {
        LOG_ERR("getting a value from the IPC cache failed (addr=%p)", ptr);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    file_ipc_data_t *file_ipc_data = (file_ipc_data_t *)providerIpcData;
    file_ipc_data->offset_fd = (size_t)value - 1;
    file_ipc_data->size = size;
    strncpy(file_ipc_data->path, file_provider->path, PATH_MAX - 1);
    file_ipc_data->path[PATH_MAX - 1] = '\0';
    file_ipc_data->protection = file_provider->protection;
    file_ipc_data->visibility = file_provider->visibility;

    return UMF_RESULT_SUCCESS;
}

static umf_result_t file_put_ipc_handle(void *provider, void *providerIpcData) {
    file_memory_provider_t *file_provider = (file_memory_provider_t *)provider;
    if (!file_provider->IPC_enabled) {
        LOG_ERR("memory visibility mode is not UMF_MEM_MAP_SHARED")
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
    file_memory_provider_t *file_provider = (file_memory_provider_t *)provider;
    if (!file_provider->IPC_enabled) {
        LOG_ERR("memory visibility mode is not UMF_MEM_MAP_SHARED")
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    file_ipc_data_t *file_ipc_data = (file_ipc_data_t *)providerIpcData;
    umf_result_t ret = UMF_RESULT_SUCCESS;
    int fd;

    size_t offset_aligned = file_ipc_data->offset_fd;
    size_t size_aligned = file_ipc_data->size;

    if (file_provider->is_fsdax) {
        // It is just a workaround for case when
        // file_alloc() was called with the size argument
        // that is not a multiplier of FSDAX_PAGE_SIZE_2MB.
        utils_align_ptr_down_size_up((void **)&offset_aligned, &size_aligned,
                                     FSDAX_PAGE_SIZE_2MB);
    }

    fd = utils_file_open(file_ipc_data->path);
    if (fd == -1) {
        LOG_PERR("opening the file to be mapped (%s) failed",
                 file_ipc_data->path);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    char *addr =
        utils_mmap_file(NULL, size_aligned, file_ipc_data->protection,
                        file_ipc_data->visibility, fd, offset_aligned, NULL);
    (void)utils_close_fd(fd);
    if (addr == NULL) {
        file_store_last_native_error(UMF_FILE_RESULT_ERROR_ALLOC_FAILED, errno);
        LOG_PERR("file mapping failed (path: %s, size: %zu, protection: %u, "
                 "visibility: %u, fd: %i, offset: %zu)",
                 file_ipc_data->path, size_aligned, file_ipc_data->protection,
                 file_ipc_data->visibility, fd, offset_aligned);
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    LOG_DEBUG("file mapped (path: %s, size: %zu, protection: %u, visibility: "
              "%u, fd: %i, offset: %zu) at address %p",
              file_ipc_data->path, size_aligned, file_ipc_data->protection,
              file_ipc_data->visibility, fd, offset_aligned, (void *)addr);

    *ptr = addr;

    return ret;
}

static umf_result_t file_close_ipc_handle(void *provider, void *ptr,
                                          size_t size) {
    file_memory_provider_t *file_provider = (file_memory_provider_t *)provider;
    if (!file_provider->IPC_enabled) {
        LOG_ERR("memory visibility mode is not UMF_MEM_MAP_SHARED")
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (file_provider->is_fsdax) {
        // It is just a workaround for case when
        // file_alloc() was called with the size argument
        // that is not a multiplier of FSDAX_PAGE_SIZE_2MB.
        utils_align_ptr_down_size_up(&ptr, &size, FSDAX_PAGE_SIZE_2MB);
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

static umf_result_t file_free(void *provider, void *ptr, size_t size) {
    file_memory_provider_t *file_provider = (file_memory_provider_t *)provider;
    return coarse_free(file_provider->coarse, ptr, size);
}

static umf_memory_provider_ops_t UMF_FILE_MEMORY_PROVIDER_OPS = {
    .version = UMF_PROVIDER_OPS_VERSION_CURRENT,
    .initialize = file_initialize,
    .finalize = file_finalize,
    .alloc = file_alloc,
    .free = file_free,
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

const umf_memory_provider_ops_t *umfFileMemoryProviderOps(void) {
    return &UMF_FILE_MEMORY_PROVIDER_OPS;
}

umf_result_t umfFileMemoryProviderParamsCreate(
    umf_file_memory_provider_params_handle_t *hParams, const char *path) {
    libumfInit();
    if (hParams == NULL) {
        LOG_ERR("File Memory Provider params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (path == NULL) {
        LOG_ERR("File path is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_file_memory_provider_params_handle_t params =
        umf_ba_global_alloc(sizeof(*params));
    if (params == NULL) {
        LOG_ERR("allocating memory for File Memory Provider params failed");
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    params->path = NULL;
    params->protection = UMF_PROTECTION_READ | UMF_PROTECTION_WRITE;
    params->visibility = UMF_MEM_MAP_PRIVATE;

    umf_result_t res = umfFileMemoryProviderParamsSetPath(params, path);
    if (res != UMF_RESULT_SUCCESS) {
        umf_ba_global_free(params);
        return res;
    }

    *hParams = params;

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfFileMemoryProviderParamsDestroy(
    umf_file_memory_provider_params_handle_t hParams) {
    if (hParams != NULL) {
        umf_ba_global_free(hParams->path);
        umf_ba_global_free(hParams);
    }

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfFileMemoryProviderParamsSetPath(
    umf_file_memory_provider_params_handle_t hParams, const char *path) {
    if (hParams == NULL) {
        LOG_ERR("File Memory Provider params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (path == NULL) {
        LOG_ERR("File path is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    size_t len = strlen(path);
    if (len == 0) {
        LOG_ERR("File path is empty");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    len += 1; // for the null terminator
    char *new_path = NULL;
    new_path = umf_ba_global_alloc(len);
    if (new_path == NULL) {
        LOG_ERR("allocating memory for the file path failed");
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    strncpy(new_path, path, len);

    umf_ba_global_free(hParams->path);
    hParams->path = new_path;

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfFileMemoryProviderParamsSetProtection(
    umf_file_memory_provider_params_handle_t hParams, unsigned protection) {
    if (hParams == NULL) {
        LOG_ERR("File Memory Provider params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hParams->protection = protection;

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfFileMemoryProviderParamsSetVisibility(
    umf_file_memory_provider_params_handle_t hParams,
    umf_memory_visibility_t visibility) {
    if (hParams == NULL) {
        LOG_ERR("File Memory Provider params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hParams->visibility = visibility;

    return UMF_RESULT_SUCCESS;
}

#endif // !defined(_WIN32) && !defined(UMF_NO_HWLOC)
