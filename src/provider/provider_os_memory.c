/*
 * Copyright (C) 2022-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <assert.h>
#include <errno.h>
#include <hwloc.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base_alloc_global.h"
#include "critnib.h"
#include "provider_os_memory_internal.h"
#include "utils_log.h"

#include <umf.h>
#include <umf/memory_provider_ops.h>
#include <umf/providers/provider_os_memory.h>

#define NODESET_STR_BUF_LEN 1024

typedef struct os_memory_provider_t {
    unsigned protection; // combination of OS-specific protection flags
    unsigned visibility; // memory visibility mode
    int fd;              // file descriptor for memory mapping
    size_t size_fd;      // size of file used for memory mapping
    size_t max_size_fd;  // maximum size of file used for memory mapping
    // A critnib map storing (ptr, fd_offset + 1) pairs (+ 1 to be able to store fd_offset == 0).
    // It is needed mainly in the get_ipc_handle and open_ipc_handle hooks to mmap a specific part of a file.
    critnib *fd_offset_map;

    // NUMA config
    hwloc_bitmap_t nodeset;
    char *nodeset_str_buf;
    hwloc_membind_policy_t numa_policy;
    int numa_flags; // combination of hwloc flags

    hwloc_topology_t topo;
} os_memory_provider_t;

#define TLS_MSG_BUF_LEN 1024

typedef struct os_last_native_error_t {
    int32_t native_error;
    int errno_value;
    char msg_buff[TLS_MSG_BUF_LEN];
} os_last_native_error_t;

static __TLS os_last_native_error_t TLS_last_native_error;

// helper values used only in the Native_error_str array
#define _UMF_OS_RESULT_SUCCESS (UMF_OS_RESULT_SUCCESS - UMF_OS_RESULT_SUCCESS)
#define _UMF_OS_RESULT_ERROR_ALLOC_FAILED                                      \
    (UMF_OS_RESULT_ERROR_ALLOC_FAILED - UMF_OS_RESULT_SUCCESS)
#define _UMF_OS_RESULT_ERROR_ADDRESS_NOT_ALIGNED                               \
    (UMF_OS_RESULT_ERROR_ADDRESS_NOT_ALIGNED - UMF_OS_RESULT_SUCCESS)
#define _UMF_OS_RESULT_ERROR_BIND_FAILED                                       \
    (UMF_OS_RESULT_ERROR_BIND_FAILED - UMF_OS_RESULT_SUCCESS)
#define _UMF_OS_RESULT_ERROR_FREE_FAILED                                       \
    (UMF_OS_RESULT_ERROR_FREE_FAILED - UMF_OS_RESULT_SUCCESS)
#define _UMF_OS_RESULT_ERROR_PURGE_LAZY_FAILED                                 \
    (UMF_OS_RESULT_ERROR_PURGE_LAZY_FAILED - UMF_OS_RESULT_SUCCESS)
#define _UMF_OS_RESULT_ERROR_PURGE_FORCE_FAILED                                \
    (UMF_OS_RESULT_ERROR_PURGE_FORCE_FAILED - UMF_OS_RESULT_SUCCESS)
#define _UMF_OS_RESULT_ERROR_TOPO_DISCOVERY_FAILED                             \
    (UMF_OS_RESULT_ERROR_TOPO_DISCOVERY_FAILED - UMF_OS_RESULT_SUCCESS)

static const char *Native_error_str[] = {
    [_UMF_OS_RESULT_SUCCESS] = "success",
    [_UMF_OS_RESULT_ERROR_ALLOC_FAILED] = "memory allocation failed",
    [_UMF_OS_RESULT_ERROR_ADDRESS_NOT_ALIGNED] =
        "allocated address is not aligned",
    [_UMF_OS_RESULT_ERROR_BIND_FAILED] = "binding memory to NUMA node failed",
    [_UMF_OS_RESULT_ERROR_FREE_FAILED] = "memory deallocation failed",
    [_UMF_OS_RESULT_ERROR_PURGE_LAZY_FAILED] = "lazy purging failed",
    [_UMF_OS_RESULT_ERROR_PURGE_FORCE_FAILED] = "force purging failed",
    [_UMF_OS_RESULT_ERROR_TOPO_DISCOVERY_FAILED] =
        "HWLOC topology discovery failed",
};

static void os_store_last_native_error(int32_t native_error, int errno_value) {
    TLS_last_native_error.native_error = native_error;
    TLS_last_native_error.errno_value = errno_value;
}

static umf_result_t nodemask_to_hwloc_nodeset(const unsigned *nodelist,
                                              unsigned long listsize,
                                              hwloc_bitmap_t *out_nodeset) {
    if (out_nodeset == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *out_nodeset = hwloc_bitmap_alloc();
    if (!*out_nodeset) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    if (listsize == 0) {
        return UMF_RESULT_SUCCESS;
    }

    for (unsigned long i = 0; i < listsize; i++) {
        if (hwloc_bitmap_set(*out_nodeset, nodelist[i])) {
            hwloc_bitmap_free(*out_nodeset);
            return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        }
    }

    return UMF_RESULT_SUCCESS;
}

umf_result_t os_translate_flags(unsigned in_flags, unsigned max,
                                umf_result_t (*translate_flag)(unsigned,
                                                               unsigned *),
                                unsigned *out_flags) {
    unsigned out_f = 0;
    for (unsigned n = 1; n < max; n <<= 1) {
        if (in_flags & n) {
            unsigned flag;
            umf_result_t result = translate_flag(n, &flag);
            if (result != UMF_RESULT_SUCCESS) {
                return result;
            }
            out_f |= flag;
            in_flags &= ~n; // clear this bit
        }
    }

    if (in_flags != 0) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *out_flags = out_f;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t translate_numa_mode(umf_numa_mode_t mode, int nodemaskEmpty,
                                        hwloc_membind_policy_t *numa_policy) {
    switch (mode) {
    case UMF_NUMA_MODE_DEFAULT:
        if (!nodemaskEmpty) {
            // nodeset must be empty
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
        *numa_policy = HWLOC_MEMBIND_DEFAULT;
        return UMF_RESULT_SUCCESS;
    case UMF_NUMA_MODE_BIND:
        if (nodemaskEmpty) {
            // nodeset must not be empty
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
        *numa_policy = HWLOC_MEMBIND_BIND;
        return UMF_RESULT_SUCCESS;
    case UMF_NUMA_MODE_INTERLEAVE:
        if (nodemaskEmpty) {
            // nodeset must not be empty
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
        *numa_policy = HWLOC_MEMBIND_INTERLEAVE;
        return UMF_RESULT_SUCCESS;
    case UMF_NUMA_MODE_PREFERRED:
        *numa_policy = HWLOC_MEMBIND_BIND;
        return UMF_RESULT_SUCCESS;
    case UMF_NUMA_MODE_LOCAL:
        if (!nodemaskEmpty) {
            // nodeset must be empty
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
        *numa_policy = HWLOC_MEMBIND_BIND;
        return UMF_RESULT_SUCCESS;
    }
    return UMF_RESULT_ERROR_INVALID_ARGUMENT;
}

static int getHwlocMembindFlags(umf_numa_mode_t mode) {
    /* UMF always operates on NUMA nodes */
    int flags = HWLOC_MEMBIND_BYNODESET;
    if (mode == UMF_NUMA_MODE_BIND) {
        /* HWLOC uses MPOL_PREFERRED[_MANY] unless HWLOC_MEMBIND_STRICT is specified */
        flags |= HWLOC_MEMBIND_STRICT;
    }
    return flags;
}

static umf_result_t translate_params(umf_os_memory_provider_params_t *in_params,
                                     os_memory_provider_t *provider) {
    umf_result_t result;

    result = os_translate_mem_protection_flags(in_params->protection,
                                               &provider->protection);
    if (result != UMF_RESULT_SUCCESS) {
        LOG_ERR("incorrect memory protection flags: %u", in_params->protection);
        return result;
    }

    result = os_translate_mem_visibility_flag(in_params->visibility,
                                              &provider->visibility);
    if (result != UMF_RESULT_SUCCESS) {
        LOG_ERR("incorrect memory visibility flag: %u", in_params->visibility);
        return result;
    }

    provider->fd = os_create_anonymous_fd(provider->visibility);
    if (provider->fd == -1) {
        LOG_PERR(
            "creating an anonymous file descriptor for memory mapping failed");
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    provider->size_fd = 0; // will be increased during each allocation
    provider->max_size_fd = get_max_file_size();

    if (provider->fd > 0) {
        int ret = os_set_file_size(provider->fd, provider->max_size_fd);
        if (ret) {
            LOG_ERR("setting file size %zu failed", provider->max_size_fd);
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
    }

    LOG_DEBUG("size of the memory mapped file set to %zu",
              provider->max_size_fd);

    // NUMA config
    int emptyNodeset = in_params->numa_list_len == 0;
    result = translate_numa_mode(in_params->numa_mode, emptyNodeset,
                                 &provider->numa_policy);
    if (result != UMF_RESULT_SUCCESS) {
        LOG_ERR("incorrect NUMA mode (%u) or wrong params",
                in_params->numa_mode);
        return result;
    }
    LOG_INFO("established HWLOC NUMA policy: %u", provider->numa_policy);

    provider->numa_flags = getHwlocMembindFlags(in_params->numa_mode);

    return nodemask_to_hwloc_nodeset(
        in_params->numa_list, in_params->numa_list_len, &provider->nodeset);
}

static umf_result_t os_initialize(void *params, void **provider) {
    umf_result_t ret;

    if (provider == NULL || params == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_os_memory_provider_params_t *in_params =
        (umf_os_memory_provider_params_t *)params;

    if (in_params->visibility == UMF_MEM_MAP_SHARED &&
        in_params->numa_mode != UMF_NUMA_MODE_DEFAULT) {
        LOG_ERR("Unsupported NUMA mode for the UMF_MEM_MAP_SHARED memory "
                "visibility mode (only the UMF_NUMA_MODE_DEFAULT is supported "
                "for now)");
        return UMF_RESULT_ERROR_NOT_SUPPORTED;
    }

    os_memory_provider_t *os_provider =
        umf_ba_global_alloc(sizeof(os_memory_provider_t));
    if (!os_provider) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    memset(os_provider, 0, sizeof(*os_provider));

    int r = hwloc_topology_init(&os_provider->topo);
    if (r) {
        LOG_ERR("HWLOC topology init failed");
        ret = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        goto err_free_os_provider;
    }

    r = hwloc_topology_load(os_provider->topo);
    if (r) {
        os_store_last_native_error(UMF_OS_RESULT_ERROR_TOPO_DISCOVERY_FAILED,
                                   0);
        LOG_ERR("HWLOC topology discovery failed");
        ret = UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
        goto err_destroy_hwloc_topology;
    }

    ret = translate_params(in_params, os_provider);
    if (ret != UMF_RESULT_SUCCESS) {
        goto err_destroy_hwloc_topology;
    }

    os_provider->nodeset_str_buf = umf_ba_global_alloc(NODESET_STR_BUF_LEN);
    if (!os_provider->nodeset_str_buf) {
        LOG_INFO("allocating memory for printing NUMA nodes failed");
    } else {
        if (hwloc_bitmap_list_snprintf(os_provider->nodeset_str_buf,
                                       NODESET_STR_BUF_LEN,
                                       os_provider->nodeset)) {
            LOG_INFO("OS provider initialized with NUMA nodes: %s",
                     os_provider->nodeset_str_buf);
        } else if (hwloc_bitmap_iszero(os_provider->nodeset)) {
            LOG_INFO("OS provider initialized with empty NUMA nodeset");
        }
    }

    os_provider->fd_offset_map = critnib_new();
    if (!os_provider->fd_offset_map) {
        LOG_ERR("creating file descriptor offset map failed");
        ret = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        goto err_free_nodeset_str_buf;
    }

    *provider = os_provider;

    return UMF_RESULT_SUCCESS;

err_free_nodeset_str_buf:
    umf_ba_global_free(os_provider->nodeset_str_buf);
err_destroy_hwloc_topology:
    hwloc_topology_destroy(os_provider->topo);
err_free_os_provider:
    umf_ba_global_free(os_provider);
    return ret;
}

static void os_finalize(void *provider) {
    if (provider == NULL) {
        assert(0);
        return;
    }

    os_memory_provider_t *os_provider = provider;

    critnib_delete(os_provider->fd_offset_map);

    if (os_provider->nodeset_str_buf) {
        umf_ba_global_free(os_provider->nodeset_str_buf);
    }

    hwloc_bitmap_free(os_provider->nodeset);
    hwloc_topology_destroy(os_provider->topo);
    umf_ba_global_free(os_provider);
}

static umf_result_t os_get_min_page_size(void *provider, void *ptr,
                                         size_t *page_size);

// TODO: this function should be reenabled when CTL is implemented
#if 0
static void print_numa_nodes(os_memory_provider_t *os_provider, void *addr,
                             size_t size) {

    if (os_provider->nodeset_str_buf == NULL) {
        LOG_DEBUG("cannot print assigned NUMA node due to allocation "
                  "failure in os_initialize()");
        return;
    }

    hwloc_bitmap_t nodeset = hwloc_bitmap_alloc();
    if (!nodeset) {
        LOG_DEBUG("cannot print assigned NUMA node due to allocation failure");
        return;
    }

    int ret = hwloc_get_area_memlocation(os_provider->topo, addr, 1, nodeset,
                                         HWLOC_MEMBIND_BYNODESET);
    if (ret) {
        LOG_PDEBUG("cannot print assigned NUMA node (errno = %i)", errno);
    } else {
        if (hwloc_bitmap_list_snprintf(os_provider->nodeset_str_buf,
                                       NODESET_STR_BUF_LEN, nodeset)) {
            LOG_DEBUG("alloc(%zu) = 0x%llx, allocate on NUMA nodes = %s",
                      size, (unsigned long long)addr,
                      os_provider->nodeset_str_buf);
        } else {
            LOG_DEBUG("cannot print assigned NUMA node");
        }
    }

    hwloc_bitmap_free(nodeset);
}
#endif

static inline void assert_is_page_aligned(uintptr_t ptr, size_t page_size) {
    assert((ptr & (page_size - 1)) == 0);
    (void)ptr;       // unused in Release build
    (void)page_size; // unused in Release build
}

static int os_mmap_aligned(void *hint_addr, size_t length, size_t alignment,
                           size_t page_size, int prot, int flag, int fd,
                           size_t max_fd_size, void **out_addr,
                           size_t *fd_size) {
    assert(out_addr);

    size_t extended_length = length;

    if (alignment > page_size) {
        // We have to increase length by alignment to be able to "cut out"
        // the correctly aligned part of the memory from the mapped region
        // by unmapping the rest: unaligned beginning and unaligned end
        // of this region.
        extended_length += alignment;
    }

    size_t fd_offset = 0;

    if (fd > 0) {
        fd_offset = *fd_size;
        *fd_size += extended_length;
        if (*fd_size > max_fd_size) {
            LOG_ERR("cannot grow a file size beyond %zu", max_fd_size);
            return -1;
        }
    }

    void *ptr = os_mmap(hint_addr, extended_length, prot, flag, fd, fd_offset);
    if (ptr == NULL) {
        LOG_PDEBUG("memory mapping failed");
        return -1;
    }

    if (alignment > page_size) {
        uintptr_t addr = (uintptr_t)ptr;
        uintptr_t aligned_addr = addr;
        uintptr_t rest_of_div = aligned_addr % alignment;

        if (rest_of_div) {
            aligned_addr += alignment - rest_of_div;
        }

        assert_is_page_aligned(aligned_addr, page_size);

        size_t head_len = aligned_addr - addr;
        if (head_len > 0) {
            os_munmap(ptr, head_len);
        }

        // tail address has to page-aligned
        uintptr_t tail = aligned_addr + length;
        if (tail & (page_size - 1)) {
            tail = (tail + page_size) & ~(page_size - 1);
        }

        assert_is_page_aligned(tail, page_size);
        assert(tail >= aligned_addr + length);

        size_t tail_len = (addr + extended_length) - tail;
        if (tail_len > 0) {
            os_munmap((void *)tail, tail_len);
        }

        *out_addr = (void *)aligned_addr;
        return 0;
    }

    *out_addr = ptr;
    return 0;
}

static umf_result_t os_alloc(void *provider, size_t size, size_t alignment,
                             void **resultPtr) {
    int ret;

    if (provider == NULL || resultPtr == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    os_memory_provider_t *os_provider = (os_memory_provider_t *)provider;

    size_t page_size;
    umf_result_t result = os_get_min_page_size(provider, NULL, &page_size);
    if (result != UMF_RESULT_SUCCESS) {
        return result;
    }

    if (alignment && (alignment % page_size) && (page_size % alignment)) {
        LOG_ERR("wrong alignment: %zu (not a multiple or a divider of the "
                "minimum page size (%zu))",
                alignment, page_size);

        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    size_t fd_offset = os_provider->size_fd; // needed for critnib_insert()

    void *addr = NULL;
    errno = 0;
    ret = os_mmap_aligned(NULL, size, alignment, page_size,
                          os_provider->protection, os_provider->visibility,
                          os_provider->fd, os_provider->max_size_fd, &addr,
                          &os_provider->size_fd);
    if (ret) {
        os_store_last_native_error(UMF_OS_RESULT_ERROR_ALLOC_FAILED, errno);
        LOG_PERR("memory allocation failed");
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    // verify the alignment
    if ((alignment > 0) && ((uintptr_t)addr % alignment)) {
        os_store_last_native_error(UMF_OS_RESULT_ERROR_ADDRESS_NOT_ALIGNED, 0);
        LOG_ERR("allocated address 0x%llx is not aligned to %zu (0x%zx) "
                "bytes",
                (unsigned long long)addr, alignment, alignment);
        goto err_unmap;
    }

    errno = 0;
    if (hwloc_bitmap_iszero(os_provider->nodeset)) {
        // Hwloc_set_area_membind fails if empty nodeset is passed so if no node is specified,
        // just pass all available nodes. For modes where no node is needed, they will be
        // ignored anyway.
        hwloc_const_nodeset_t complete_nodeset =
            hwloc_topology_get_complete_nodeset(os_provider->topo);
        ret = hwloc_set_area_membind(os_provider->topo, addr, size,
                                     complete_nodeset, os_provider->numa_policy,
                                     os_provider->numa_flags);
    } else {
        ret = hwloc_set_area_membind(
            os_provider->topo, addr, size, os_provider->nodeset,
            os_provider->numa_policy, os_provider->numa_flags);
    }

    if (ret) {
        os_store_last_native_error(UMF_OS_RESULT_ERROR_BIND_FAILED, errno);
        LOG_PERR("binding memory to NUMA node failed");
        // TODO: (errno == 0) when hwloc_set_area_membind() fails on Windows - ignore this temporarily
        if (errno != ENOSYS &&
            errno != 0) { // ENOSYS - Function not implemented
            // Do not error out if memory binding is not implemented at all (like in case of WSL on Windows).
            goto err_unmap;
        }
    }

    if (os_provider->fd > 0) {
        // store (fd_offset + 1) to be able to store fd_offset == 0
        ret =
            critnib_insert(os_provider->fd_offset_map, (uintptr_t)addr,
                           (void *)(uintptr_t)(fd_offset + 1), 0 /* update */);
        if (ret) {
            LOG_ERR("os_alloc(): inserting a value to the file descriptor "
                    "offset map failed (addr=%p, offset=%zu)",
                    addr, fd_offset);
        }
    }

    *resultPtr = addr;

    return UMF_RESULT_SUCCESS;

err_unmap:
    (void)os_munmap(addr, size);
    return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
}

static umf_result_t os_free(void *provider, void *ptr, size_t size) {
    if (provider == NULL || ptr == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    os_memory_provider_t *os_provider = (os_memory_provider_t *)provider;

    if (os_provider->fd > 0) {
        critnib_remove(os_provider->fd_offset_map, (uintptr_t)ptr);
    }

    errno = 0;
    int ret = os_munmap(ptr, size);
    // ignore error when size == 0
    if (ret && (size > 0)) {
        os_store_last_native_error(UMF_OS_RESULT_ERROR_FREE_FAILED, errno);
        LOG_PERR("memory deallocation failed");

        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    return UMF_RESULT_SUCCESS;
}

static void os_get_last_native_error(void *provider, const char **ppMessage,
                                     int32_t *pError) {
    (void)provider; // unused

    if (ppMessage == NULL || pError == NULL) {
        assert(0);
        return;
    }

    *pError = TLS_last_native_error.native_error;
    if (TLS_last_native_error.errno_value == 0) {
        *ppMessage = Native_error_str[*pError - UMF_OS_RESULT_SUCCESS];
        return;
    }

    const char *msg;
    size_t len;
    size_t pos = 0;

    msg = Native_error_str[*pError - UMF_OS_RESULT_SUCCESS];
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

static umf_result_t os_get_recommended_page_size(void *provider, size_t size,
                                                 size_t *page_size) {
    (void)size; // unused

    if (provider == NULL || page_size == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *page_size = os_get_page_size();

    return UMF_RESULT_SUCCESS;
}

static umf_result_t os_get_min_page_size(void *provider, void *ptr,
                                         size_t *page_size) {
    (void)ptr; // unused

    return os_get_recommended_page_size(provider, 0, page_size);
}

static umf_result_t os_purge_lazy(void *provider, void *ptr, size_t size) {
    if (provider == NULL || ptr == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    errno = 0;
    if (os_purge(ptr, size, UMF_PURGE_LAZY)) {
        os_store_last_native_error(UMF_OS_RESULT_ERROR_PURGE_LAZY_FAILED,
                                   errno);
        LOG_PERR("lazy purging failed");

        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }
    return UMF_RESULT_SUCCESS;
}

static umf_result_t os_purge_force(void *provider, void *ptr, size_t size) {
    if (provider == NULL || ptr == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    errno = 0;
    if (os_purge(ptr, size, UMF_PURGE_FORCE)) {
        os_store_last_native_error(UMF_OS_RESULT_ERROR_PURGE_FORCE_FAILED,
                                   errno);
        LOG_PERR("force purging failed");
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }
    return UMF_RESULT_SUCCESS;
}

static const char *os_get_name(void *provider) {
    (void)provider; // unused
    return "OS";
}

static umf_result_t os_allocation_split(void *provider, void *ptr,
                                        size_t totalSize, size_t firstSize) {
    (void)totalSize;

    os_memory_provider_t *os_provider = (os_memory_provider_t *)provider;
    if (os_provider->fd <= 0) {
        return UMF_RESULT_SUCCESS;
    }

    void *value = critnib_get(os_provider->fd_offset_map, (uintptr_t)ptr);
    if (value == NULL) {
        LOG_ERR("os_allocation_split(): getting a value from the file "
                "descriptor offset map failed (addr=%p)",
                ptr);
    } else {
        uintptr_t new_key = (uintptr_t)ptr + firstSize;
        void *new_value = (void *)((uintptr_t)value + firstSize);
        int ret = critnib_insert(os_provider->fd_offset_map, new_key, new_value,
                                 0 /* update */);
        if (ret) {
            LOG_ERR("os_allocation_split(): inserting a value to the file "
                    "descriptor offset map failed (addr=%p, offset=%zu)",
                    (void *)new_key, (size_t)new_value - 1);
        }
    }

    return UMF_RESULT_SUCCESS;
}

static umf_result_t os_allocation_merge(void *provider, void *lowPtr,
                                        void *highPtr, size_t totalSize) {
    (void)lowPtr;
    (void)totalSize;

    os_memory_provider_t *os_provider = (os_memory_provider_t *)provider;
    if (os_provider->fd <= 0) {
        return UMF_RESULT_SUCCESS;
    }

    void *value =
        critnib_remove(os_provider->fd_offset_map, (uintptr_t)highPtr);
    if (value == NULL) {
        LOG_ERR("os_allocation_merge(): removing a value from the file "
                "descriptor offset map failed (addr=%p)",
                highPtr);
    }

    return UMF_RESULT_SUCCESS;
}

static umf_memory_provider_ops_t UMF_OS_MEMORY_PROVIDER_OPS = {
    .version = UMF_VERSION_CURRENT,
    .initialize = os_initialize,
    .finalize = os_finalize,
    .alloc = os_alloc,
    .free = os_free,
    .get_last_native_error = os_get_last_native_error,
    .get_recommended_page_size = os_get_recommended_page_size,
    .get_min_page_size = os_get_min_page_size,
    .get_name = os_get_name,
    .ext.purge_lazy = os_purge_lazy,
    .ext.purge_force = os_purge_force,
    .ext.allocation_merge = os_allocation_merge,
    .ext.allocation_split = os_allocation_split,
    .ipc.get_ipc_handle_size = NULL,
    .ipc.get_ipc_handle = NULL,
    .ipc.put_ipc_handle = NULL,
    .ipc.open_ipc_handle = NULL,
    .ipc.close_ipc_handle = NULL};

umf_memory_provider_ops_t *umfOsMemoryProviderOps(void) {
    return &UMF_OS_MEMORY_PROVIDER_OPS;
}
