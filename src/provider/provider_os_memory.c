/*
 * Copyright (C) 2022-2024 Intel Corporation
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

#include <umf.h>
#include <umf/memory_provider_ops.h>
#include <umf/providers/provider_os_memory.h>

// OS Memory Provider requires HWLOC
#if defined(UMF_NO_HWLOC)

umf_memory_provider_ops_t *umfOsMemoryProviderOps(void) { return NULL; }

#else // !defined(UMF_NO_HWLOC)

#include "base_alloc_global.h"
#include "critnib.h"
#include "provider_os_memory_internal.h"
#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_log.h"

#define NODESET_STR_BUF_LEN 1024

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

static umf_result_t initialize_nodeset(os_memory_provider_t *os_provider,
                                       const unsigned *nodelist,
                                       unsigned long listsize,
                                       int is_separate_nodes) {

    unsigned long array_size = (listsize && is_separate_nodes) ? listsize : 1;
    os_provider->nodeset =
        umf_ba_global_alloc(sizeof(*os_provider->nodeset) * array_size);

    if (!os_provider->nodeset) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    hwloc_bitmap_t *out_nodeset = os_provider->nodeset;
    os_provider->nodeset_len = array_size;
    if (listsize == 0) {
        // Hwloc_set_area_membind fails if empty nodeset is passed so
        // if no node is specified, just pass all available nodes.
        // For modes where no node is needed, they will be ignored anyway.
        out_nodeset[0] = hwloc_bitmap_dup(
            hwloc_topology_get_complete_nodeset(os_provider->topo));
        if (!out_nodeset[0]) {
            goto err_free_list;
        }
        return UMF_RESULT_SUCCESS;
    }

    for (unsigned long i = 0; i < array_size; i++) {
        out_nodeset[i] = hwloc_bitmap_alloc();
        if (!out_nodeset[i]) {
            for (unsigned long j = 0; j < i; j++) {
                hwloc_bitmap_free(out_nodeset[j]);
            }
            goto err_free_list;
        }
    }

    if (is_separate_nodes) {
        for (unsigned long i = 0; i < listsize; i++) {
            if (hwloc_bitmap_set(out_nodeset[i], nodelist[i])) {
                goto err_free_bitmaps;
            }
        }
    } else {
        for (unsigned long i = 0; i < listsize; i++) {
            if (hwloc_bitmap_set(out_nodeset[0], nodelist[i])) {
                goto err_free_bitmaps;
            }
        }
    }

    return UMF_RESULT_SUCCESS;

err_free_bitmaps:
    for (unsigned long i = 0; i < array_size; i++) {
        hwloc_bitmap_free(out_nodeset[i]);
    }
err_free_list:
    umf_ba_global_free(*out_nodeset);
    os_provider->nodeset_len = 0;
    return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
}

static umf_result_t validate_numa_mode(umf_numa_mode_t mode,
                                       int nodemaskEmpty) {
    switch (mode) {
    case UMF_NUMA_MODE_DEFAULT:
    case UMF_NUMA_MODE_LOCAL:
        if (!nodemaskEmpty) {
            // nodeset must be empty
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
        return UMF_RESULT_SUCCESS;
    case UMF_NUMA_MODE_BIND:
    case UMF_NUMA_MODE_INTERLEAVE:
    case UMF_NUMA_MODE_SPLIT:
        if (nodemaskEmpty) {
            // nodeset must not be empty
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
        return UMF_RESULT_SUCCESS;
    case UMF_NUMA_MODE_PREFERRED:
        return UMF_RESULT_SUCCESS;
    default:
        assert(0);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
}

static hwloc_membind_policy_t translate_numa_mode(umf_numa_mode_t mode,
                                                  int dedicated_node_bind) {
    switch (mode) {
    case UMF_NUMA_MODE_DEFAULT:
        return HWLOC_MEMBIND_DEFAULT;
    case UMF_NUMA_MODE_BIND:
    case UMF_NUMA_MODE_SPLIT:
        return HWLOC_MEMBIND_BIND;
    case UMF_NUMA_MODE_INTERLEAVE:
        // In manual mode, we manually implement interleaving,
        // by binding memory to specific NUMA nodes.
        if (dedicated_node_bind) {
            return HWLOC_MEMBIND_BIND;
        }
        return HWLOC_MEMBIND_INTERLEAVE;
    case UMF_NUMA_MODE_PREFERRED:
        return HWLOC_MEMBIND_BIND;
    case UMF_NUMA_MODE_LOCAL:
        return HWLOC_MEMBIND_BIND;
    }
    assert(0);
    return -1;
}

//return 1 if umf will bind memory directly to single NUMA node, based on internal algorithm
//return 0 if umf will just set numa memory policy, and kernel will decide where to allocate memory
static int dedicated_node_bind(umf_os_memory_provider_params_t *in_params) {
    if (in_params->numa_mode == UMF_NUMA_MODE_INTERLEAVE) {
        return in_params->part_size > 0;
    }
    if (in_params->numa_mode == UMF_NUMA_MODE_SPLIT) {
        return 1;
    }
    return 0;
}

static int getHwlocMembindFlags(umf_numa_mode_t mode, int dedicated_node_bind) {
    /* UMF always operates on NUMA nodes */
    int flags = HWLOC_MEMBIND_BYNODESET;
    if (mode == UMF_NUMA_MODE_BIND) {
        /* HWLOC uses MPOL_PREFERRED[_MANY] unless HWLOC_MEMBIND_STRICT is specified */
        flags |= HWLOC_MEMBIND_STRICT;
    }
    if (dedicated_node_bind) {
        flags |= HWLOC_MEMBIND_STRICT;
    }
    return flags;
}

static int validate_and_copy_shm_name(const char *in_shm_name,
                                      char out_shm_name[NAME_MAX]) {
    // shm_name must not contain any slashes
    if (strchr(in_shm_name, '/')) {
        LOG_ERR("name of a shared memory file must not contain any slashes: %s",
                in_shm_name);
        return -1;
    }

    // (- 2) because there should be a room for the initial slash ('/')
    // that we will add at the beginning and the terminating null byte ('\0')
    size_t max_len = NAME_MAX - 2;

    if (strlen(in_shm_name) > max_len) {
        LOG_ERR("name of a shared memory file is longer than %zu bytes",
                max_len);
        return -1;
    }

    out_shm_name[0] = '/'; // the initial slash
    strncpy(&out_shm_name[1], in_shm_name, max_len);
    out_shm_name[NAME_MAX - 1] = '\0'; // the terminating null byte

    return 0;
}

static umf_result_t
create_fd_for_mmap(umf_os_memory_provider_params_t *in_params,
                   os_memory_provider_t *provider) {
    umf_result_t result;

    // size_fd will be increased during each allocation if (provider->fd > 0)
    provider->size_fd = 0;
    provider->shm_name[0] = '\0'; // zero shm_name

    if (in_params->visibility != UMF_MEM_MAP_SHARED) {
        provider->fd = -1;
        provider->max_size_fd = 0;
        return UMF_RESULT_SUCCESS;
    }

    /* visibility == UMF_MEM_MAP_SHARED */

    provider->max_size_fd = get_max_file_size();

    if (in_params->shm_name) {
        if (validate_and_copy_shm_name(in_params->shm_name,
                                       provider->shm_name)) {
            LOG_ERR("invalid name of a shared memory file: %s",
                    in_params->shm_name);
            return -1;
        }

        /* create a new shared memory file */
        provider->fd =
            utils_shm_create(in_params->shm_name, provider->max_size_fd);
        if (provider->fd == -1) {
            LOG_ERR("creating a shared memory file /dev/shm/%s of size %zu for "
                    "memory mapping failed",
                    in_params->shm_name, provider->max_size_fd);
            provider->shm_name[0] = '\0'; // zero shm_name
            return -1;
        }

        LOG_DEBUG("created the shared memory file /dev/shm/%s of size %zu",
                  in_params->shm_name, provider->max_size_fd);

        return UMF_RESULT_SUCCESS;
    }

    provider->fd = utils_create_anonymous_fd();
    if (provider->fd <= 0) {
        LOG_ERR(
            "creating an anonymous file descriptor for memory mapping failed");
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    int ret = utils_set_file_size(provider->fd, provider->max_size_fd);
    if (ret) {
        LOG_ERR("setting size %zu of an anonymous file failed",
                provider->max_size_fd);
        result = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err_close_file;
    }

    LOG_DEBUG("size of the anonymous file set to %zu", provider->max_size_fd);

    return UMF_RESULT_SUCCESS;

err_close_file:
    if (provider->fd > 0) {
        (void)utils_close_fd(provider->fd);
    }

    return result;
}

static umf_result_t
validatePartitions(umf_os_memory_provider_params_t *params) {

    if (params->partitions_len == 0) {
        return UMF_RESULT_SUCCESS;
    }
    for (unsigned i = 0; i < params->partitions_len; i++) {
        int found = 0;
        if (params->partitions[i].weight == 0) {
            LOG_ERR("partition weight cannot be zero");
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
        for (unsigned j = 0; j < params->numa_list_len; j++) {
            if (params->numa_list[j] == params->partitions[i].target) {
                found = 1;
                break;
            }
        }
        if (!found) {
            LOG_ERR("partition target %u, not found in numa_list",
                    params->partitions[i].target);
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
    }

    return UMF_RESULT_SUCCESS;
}

static void free_bitmaps(os_memory_provider_t *provider) {
    for (unsigned i = 0; i < provider->nodeset_len; i++) {
        hwloc_bitmap_free(provider->nodeset[i]);
    }
    umf_ba_global_free(provider->nodeset);
}

static umf_result_t
initializePartitions(os_memory_provider_t *provider,
                     umf_os_memory_provider_params_t *in_params) {
    if (provider->mode != UMF_NUMA_MODE_SPLIT) {
        return UMF_RESULT_SUCCESS;
    }

    provider->partitions_len = in_params->partitions_len
                                   ? in_params->partitions_len
                                   : in_params->numa_list_len;

    provider->partitions = umf_ba_global_alloc(sizeof(*provider->partitions) *
                                               provider->partitions_len);

    if (!provider->partitions) {
        LOG_ERR("allocating memory for partitions failed");
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }
    if (in_params->partitions_len == 0) {
        for (unsigned i = 0; i < provider->partitions_len; i++) {
            provider->partitions[i].weight = 1;
            provider->partitions[i].target = provider->nodeset[i];
        }
        provider->partitions_weight_sum = provider->partitions_len;
    } else {
        provider->partitions_weight_sum = 0;
        for (unsigned i = 0; i < in_params->partitions_len; i++) {
            provider->partitions[i].weight = in_params->partitions[i].weight;
            for (unsigned j = 0; j < in_params->numa_list_len; j++) {
                if (in_params->numa_list[j] ==
                    in_params->partitions[i].target) {
                    provider->partitions[i].target = provider->nodeset[j];
                    break;
                }
            }

            provider->partitions_weight_sum += in_params->partitions[i].weight;
        }
    }

    return UMF_RESULT_SUCCESS;
}

static umf_result_t translate_params(umf_os_memory_provider_params_t *in_params,
                                     os_memory_provider_t *provider) {
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

    // IPC API requires in_params->visibility == UMF_MEM_MAP_SHARED
    provider->IPC_enabled = (in_params->visibility == UMF_MEM_MAP_SHARED);

    // NUMA config
    int emptyNodeset = in_params->numa_list_len == 0;
    result = validate_numa_mode(in_params->numa_mode, emptyNodeset);
    if (result != UMF_RESULT_SUCCESS) {
        LOG_ERR("incorrect NUMA mode (%u) or wrong params",
                in_params->numa_mode);
        return result;
    }

    result = validatePartitions(in_params);

    if (result != UMF_RESULT_SUCCESS) {
        return result;
    }

    int is_dedicated_node_bind = dedicated_node_bind(in_params);
    provider->numa_policy =
        translate_numa_mode(in_params->numa_mode, is_dedicated_node_bind);

    LOG_INFO("established HWLOC NUMA policy: %u", provider->numa_policy);

    provider->numa_flags =
        getHwlocMembindFlags(in_params->numa_mode, is_dedicated_node_bind);
    provider->mode = in_params->numa_mode;
    provider->part_size = in_params->part_size;

    result =
        initialize_nodeset(provider, in_params->numa_list,
                           in_params->numa_list_len, is_dedicated_node_bind);
    if (result != UMF_RESULT_SUCCESS) {
        LOG_ERR("error while initializing a nodeset");
        return result;
    }

    initializePartitions(provider, in_params);

    return UMF_RESULT_SUCCESS;
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

    os_provider->fd_offset_map = critnib_new();
    if (!os_provider->fd_offset_map) {
        LOG_ERR("creating file descriptor offset map failed");
        ret = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        goto err_destroy_hwloc_topology;
    }

    ret = translate_params(in_params, os_provider);
    if (ret != UMF_RESULT_SUCCESS) {
        goto err_destroy_critnib;
    }

    ret = create_fd_for_mmap(in_params, os_provider);
    if (ret != UMF_RESULT_SUCCESS) {
        goto err_destroy_bitmaps;
    }

    if (os_provider->fd > 0) {
        if (utils_mutex_init(&os_provider->lock_fd) == NULL) {
            LOG_ERR("initializing the file size lock failed");
            ret = UMF_RESULT_ERROR_UNKNOWN;
            goto err_destroy_bitmaps;
        }
    }

    os_provider->nodeset_str_buf = umf_ba_global_alloc(NODESET_STR_BUF_LEN);
    if (!os_provider->nodeset_str_buf) {
        LOG_INFO("allocating memory for printing NUMA nodes failed");
    } else {
        LOG_INFO("OS provider initialized with NUMA nodes:");
        for (unsigned i = 0; i < os_provider->nodeset_len; i++) {
            if (hwloc_bitmap_list_snprintf(os_provider->nodeset_str_buf,
                                           NODESET_STR_BUF_LEN,
                                           os_provider->nodeset[i])) {
                LOG_INFO("%s", os_provider->nodeset_str_buf);
            }
        }
    }

    *provider = os_provider;

    return UMF_RESULT_SUCCESS;

err_destroy_bitmaps:
    free_bitmaps(os_provider);
err_destroy_critnib:
    critnib_delete(os_provider->fd_offset_map);
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

    if (os_provider->fd > 0) {
        utils_mutex_destroy_not_free(&os_provider->lock_fd);
    }

    critnib_delete(os_provider->fd_offset_map);

    free_bitmaps(os_provider);

    if (os_provider->partitions) {
        umf_ba_global_free(os_provider->partitions);
    }

    if (os_provider->nodeset_str_buf) {
        umf_ba_global_free(os_provider->nodeset_str_buf);
    }
    hwloc_topology_destroy(os_provider->topo);
    umf_ba_global_free(os_provider);
}

static umf_result_t os_get_min_page_size(void *provider, void *ptr,
                                         size_t *page_size);

// TODO: this function should be re-enabled when CTL is implemented
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

static int utils_mmap_aligned(void *hint_addr, size_t length, size_t alignment,
                              size_t page_size, int prot, int flag, int fd,
                              size_t max_fd_size, utils_mutex_t *lock_fd,
                              void **out_addr, size_t *fd_size,
                              size_t *fd_offset) {
    assert(out_addr);

    size_t extended_length = length;

    if (alignment > page_size) {
        // We have to increase length by alignment to be able to "cut out"
        // the correctly aligned part of the memory from the mapped region
        // by unmapping the rest: unaligned beginning and unaligned end
        // of this region.
        extended_length += alignment;
    }

    *fd_offset = 0;

    if (fd > 0) {
        if (utils_mutex_lock(lock_fd)) {
            LOG_ERR("locking file size failed");
            return -1;
        }

        if (*fd_size + extended_length > max_fd_size) {
            utils_mutex_unlock(lock_fd);
            LOG_ERR("cannot grow a file size beyond %zu", max_fd_size);
            return -1;
        }

        *fd_offset = *fd_size;
        *fd_size += extended_length;
        utils_mutex_unlock(lock_fd);
    }

    void *ptr =
        utils_mmap(hint_addr, extended_length, prot, flag, fd, *fd_offset);
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
            utils_munmap(ptr, head_len);
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
            utils_munmap((void *)tail, tail_len);
        }

        *out_addr = (void *)aligned_addr;
        return 0;
    }

    *out_addr = ptr;
    return 0;
}

/// membbind_t - a memory binding iterator
typedef struct membind_t {
    /// Bitmap representing the set of nodes to which memory will be bound
    hwloc_bitmap_t bitmap;
    /// Size of the memory bound to the current node
    size_t bind_size;
    /// Address of the memory for next bind
    char *addr;
    /// Total size of memory allocation left to bind
    size_t alloc_size;

    /// Current node index
    unsigned node;

    /// Size of a single memory page
    size_t page_size;

    /// Remainder from the division used to distribute pages across nodes
    size_t rest;

    /// Number of pages to allocate
    size_t pages;

    /// Pages left to bind in current node
    size_t leftover_bind;
} membind_t;

/// Advances the memory binding configuration for the next set of pages
/// If we have to bind bytes which belongs to single page to mutiliple nodes,
/// we will bind it to all nodes that those bytes belongs to - and lets kernel decide where to allocate it.
static void nextBind(os_memory_provider_t *provider, membind_t *membind) {

    // If all nodes have been processed.
    if (membind->node == provider->partitions_len) {
        // if alloc_size is not 0, it means that something is wrong
        assert(membind->alloc_size == 0);
        return;
    }

    // Reset the bitmap for next binding
    hwloc_bitmap_zero(membind->bitmap);

    // Flag to check if binding crosses partition boundaries
    int bind_border_page = 0;
    if (membind->leftover_bind != 0) {
        // if we have more than a page leftover from previous bind
        hwloc_bitmap_or(membind->bitmap, membind->bitmap,
                        provider->partitions[membind->node].target);
    } else if (membind->rest != 0) {
        // if we have less than a page leftover to bind from previous bind
        hwloc_bitmap_or(membind->bitmap, membind->bitmap,
                        provider->partitions[membind->node].target);
        membind->node++;
        bind_border_page = 1;
    }

    size_t bind = membind->leftover_bind;
    size_t rest = membind->rest;

    // Determine the number of pages to bind for the current node based on weight
    while (bind == 0) {
        // Count next "ideal" bind size
        // It will be equal to (bind + rest/weight_sum) * page_size
        bind = membind->pages * provider->partitions[membind->node].weight /
               provider->partitions_weight_sum;
        rest += membind->pages * provider->partitions[membind->node].weight %
                provider->partitions_weight_sum;

        // Adjust binding if the remainder exceeds the total weight sum
        if (rest >= provider->partitions_weight_sum) {
            bind++;
            rest -= provider->partitions_weight_sum;
        }

        // Update the bitmap to include the current node's target
        hwloc_bitmap_or(membind->bitmap, membind->bitmap,
                        provider->partitions[membind->node].target);

        // If the current node has to bind less than a page
        // we will bind next page to multiple nodes
        if (bind == 0) {
            membind->node++;
            assert(membind->node < provider->partitions_len);
            bind_border_page = 1;
        }
    }

    // Update bind size and remainder based on whether the binding crossed a partition boundary
    if (bind_border_page) {
        // this means that next page belongs to multiple nodes.
        // in this case we have to bind this page separately, and
        // process rest of the pages in the next iteration
        membind->bind_size = membind->page_size;
        membind->leftover_bind = bind - 1;
        membind->rest = rest;
    } else {
        membind->bind_size = membind->page_size * bind;
        membind->rest = rest;
        membind->leftover_bind = 0;
    }
    // if processing this node is finished move to next one
    if (membind->rest == 0 && membind->leftover_bind == 0) {
        membind->node++;
    }
}

/// Initialize membind iterator
static membind_t membindFirst(os_memory_provider_t *provider, void *addr,
                              size_t size, size_t page_size) {

    membind_t membind;
    memset(&membind, 0, sizeof(membind));

    membind.alloc_size = ALIGN_UP(size, page_size);
    membind.page_size = page_size;
    membind.addr = addr;
    membind.pages = membind.alloc_size / membind.page_size;
    if (provider->nodeset_len == 1) {
        membind.bind_size = ALIGN_UP(size, membind.page_size);
        membind.bitmap = provider->nodeset[0];
        return membind;
    }

    if (provider->mode == UMF_NUMA_MODE_INTERLEAVE) {
        assert(provider->part_size != 0);
        size_t s = utils_fetch_and_add64(&provider->alloc_sum, size);
        membind.node = (s / provider->part_size) % provider->nodeset_len;
        membind.bitmap = provider->nodeset[membind.node];
        membind.bind_size = ALIGN_UP(provider->part_size, membind.page_size);
        if (membind.bind_size > membind.alloc_size) {
            membind.bind_size = membind.alloc_size;
        }
    }

    if (provider->mode == UMF_NUMA_MODE_SPLIT) {
        membind.bitmap = hwloc_bitmap_alloc();
        if (!membind.bitmap) {
            LOG_ERR("Allocation of hwloc_bitmap failed");
            return membind;
        }
        nextBind(provider, &membind);
    }

    return membind;
}

static membind_t membindNext(os_memory_provider_t *provider,
                             membind_t membind) {
    membind.alloc_size -= membind.bind_size;
    membind.addr += membind.bind_size;
    if (membind.alloc_size == 0) {
        membind.bind_size = 0;
        if (provider->mode == UMF_NUMA_MODE_SPLIT &&
            provider->nodeset_len != 1) {
            hwloc_bitmap_free(membind.bitmap);
        }
        return membind;
    }
    assert(provider->nodeset_len != 1);

    if (provider->mode == UMF_NUMA_MODE_INTERLEAVE) {
        membind.node++;
        membind.node %= provider->nodeset_len;
        membind.bitmap = provider->nodeset[membind.node];
        membind.bind_size = ALIGN_UP(provider->part_size, membind.page_size);
        if (membind.bind_size > membind.alloc_size) {
            membind.bind_size = membind.alloc_size;
        }
    }
    if (provider->mode == UMF_NUMA_MODE_SPLIT) {
        nextBind(provider, &membind);
    }
    return membind;
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

    size_t fd_offset; // needed for critnib_insert()

    void *addr = NULL;
    errno = 0;
    ret = utils_mmap_aligned(
        NULL, size, alignment, page_size, os_provider->protection,
        os_provider->visibility, os_provider->fd, os_provider->max_size_fd,
        &os_provider->lock_fd, &addr, &os_provider->size_fd, &fd_offset);
    if (ret) {
        os_store_last_native_error(UMF_OS_RESULT_ERROR_ALLOC_FAILED, 0);
        LOG_ERR("memory allocation failed");
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

    // Bind memory to NUMA nodes if numa_policy is other than DEFAULT
    if (os_provider->numa_policy != HWLOC_MEMBIND_DEFAULT) {
        membind_t membind = membindFirst(os_provider, addr, size, page_size);
        if (membind.bitmap == NULL) {
            goto err_unmap;
        }

        do {
            errno = 0;
            ret = hwloc_set_area_membind(os_provider->topo, membind.addr,
                                         membind.bind_size, membind.bitmap,
                                         os_provider->numa_policy,
                                         os_provider->numa_flags);

            if (ret) {
                os_store_last_native_error(UMF_OS_RESULT_ERROR_BIND_FAILED,
                                           errno);
                LOG_PERR("binding memory to NUMA node failed");
                // TODO: (errno == 0) when hwloc_set_area_membind() fails on Windows,
                // ignore this temporarily
                if (errno != ENOSYS &&
                    errno != 0) { // ENOSYS - Function not implemented
                    // Do not error out if memory binding is not implemented at all
                    // (like in case of WSL on Windows).
                    goto err_unmap;
                }
            }
            membind = membindNext(os_provider, membind);
        } while (membind.alloc_size > 0);
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
    (void)utils_munmap(addr, size);
    return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
}

static umf_result_t os_free(void *provider, void *ptr, size_t size) {
    if (provider == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (ptr == NULL) {
        return UMF_RESULT_SUCCESS;
    }

    os_memory_provider_t *os_provider = (os_memory_provider_t *)provider;

    if (os_provider->fd > 0) {
        critnib_remove(os_provider->fd_offset_map, (uintptr_t)ptr);
    }

    errno = 0;
    int ret = utils_munmap(ptr, size);
    if (ret) {
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

    utils_strerror(TLS_last_native_error.errno_value,
                   TLS_last_native_error.msg_buff + pos, TLS_MSG_BUF_LEN - pos);

    *ppMessage = TLS_last_native_error.msg_buff;
}

static umf_result_t os_get_recommended_page_size(void *provider, size_t size,
                                                 size_t *page_size) {
    (void)size; // unused

    if (provider == NULL || page_size == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *page_size = utils_get_page_size();

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
    if (utils_purge(ptr, size, UMF_PURGE_LAZY)) {
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
    if (utils_purge(ptr, size, UMF_PURGE_FORCE)) {
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

// This function is supposed to be thread-safe, so it should NOT be called concurrently
// with os_allocation_merge() with the same pointer.
static umf_result_t os_allocation_split(void *provider, void *ptr,
                                        size_t totalSize, size_t firstSize) {
    (void)totalSize;

    os_memory_provider_t *os_provider = (os_memory_provider_t *)provider;
    if (os_provider->fd < 0) {
        return UMF_RESULT_SUCCESS;
    }

    void *value = critnib_get(os_provider->fd_offset_map, (uintptr_t)ptr);
    if (value == NULL) {
        LOG_ERR("os_allocation_split(): getting a value from the file "
                "descriptor offset map failed (addr=%p)",
                ptr);
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    uintptr_t new_key = (uintptr_t)ptr + firstSize;
    void *new_value = (void *)((uintptr_t)value + firstSize);
    int ret = critnib_insert(os_provider->fd_offset_map, new_key, new_value,
                             0 /* update */);
    if (ret) {
        LOG_ERR("os_allocation_split(): inserting a value to the file "
                "descriptor offset map failed (addr=%p, offset=%zu)",
                (void *)new_key, (size_t)new_value - 1);
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    return UMF_RESULT_SUCCESS;
}

// It should NOT be called concurrently with os_allocation_split() with the same pointer.
static umf_result_t os_allocation_merge(void *provider, void *lowPtr,
                                        void *highPtr, size_t totalSize) {
    (void)lowPtr;
    (void)totalSize;

    os_memory_provider_t *os_provider = (os_memory_provider_t *)provider;
    if (os_provider->fd < 0) {
        return UMF_RESULT_SUCCESS;
    }

    void *value =
        critnib_remove(os_provider->fd_offset_map, (uintptr_t)highPtr);
    if (value == NULL) {
        LOG_ERR("os_allocation_merge(): removing a value from the file "
                "descriptor offset map failed (addr=%p)",
                highPtr);
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    return UMF_RESULT_SUCCESS;
}

typedef struct os_ipc_data_t {
    int pid;
    int fd;
    size_t fd_offset;
    size_t size;
    // shm_name is a Flexible Array Member because it is optional and its size
    // varies on the Shared Memory object name
    size_t shm_name_len;
    char shm_name[];
} os_ipc_data_t;

static umf_result_t os_get_ipc_handle_size(void *provider, size_t *size) {
    if (provider == NULL || size == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    os_memory_provider_t *os_provider = (os_memory_provider_t *)provider;
    if (!os_provider->IPC_enabled) {
        LOG_ERR("memory visibility mode is not UMF_MEM_MAP_SHARED")
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    // NOTE: +1 for '\0' at the end of the string
    *size = sizeof(os_ipc_data_t) + strlen(os_provider->shm_name) + 1;

    return UMF_RESULT_SUCCESS;
}

static umf_result_t os_get_ipc_handle(void *provider, const void *ptr,
                                      size_t size, void *providerIpcData) {
    if (provider == NULL || ptr == NULL || providerIpcData == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    os_memory_provider_t *os_provider = (os_memory_provider_t *)provider;
    if (!os_provider->IPC_enabled) {
        LOG_ERR("memory visibility mode is not UMF_MEM_MAP_SHARED")
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    void *value = critnib_get(os_provider->fd_offset_map, (uintptr_t)ptr);
    if (value == NULL) {
        LOG_ERR("os_get_ipc_handle(): getting a value from the IPC cache "
                "failed (addr=%p)",
                ptr);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    os_ipc_data_t *os_ipc_data = (os_ipc_data_t *)providerIpcData;
    os_ipc_data->pid = utils_getpid();
    os_ipc_data->fd_offset = (size_t)value - 1;
    os_ipc_data->size = size;
    os_ipc_data->shm_name_len = strlen(os_provider->shm_name);
    if (os_ipc_data->shm_name_len > 0) {
        strncpy(os_ipc_data->shm_name, os_provider->shm_name,
                os_ipc_data->shm_name_len);
    } else {
        os_ipc_data->fd = os_provider->fd;
    }

    return UMF_RESULT_SUCCESS;
}

static umf_result_t os_put_ipc_handle(void *provider, void *providerIpcData) {
    if (provider == NULL || providerIpcData == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    os_memory_provider_t *os_provider = (os_memory_provider_t *)provider;
    if (!os_provider->IPC_enabled) {
        LOG_ERR("memory visibility mode is not UMF_MEM_MAP_SHARED")
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    os_ipc_data_t *os_ipc_data = (os_ipc_data_t *)providerIpcData;

    if (os_ipc_data->pid != utils_getpid()) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    size_t shm_name_len = strlen(os_provider->shm_name);
    if (shm_name_len > 0) {
        if (os_ipc_data->shm_name_len != shm_name_len) {
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        } else if (strncmp(os_ipc_data->shm_name, os_provider->shm_name,
                           shm_name_len)) {
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
    } else {
        if (os_ipc_data->fd != os_provider->fd) {
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
    }

    return UMF_RESULT_SUCCESS;
}

static umf_result_t os_open_ipc_handle(void *provider, void *providerIpcData,
                                       void **ptr) {
    if (provider == NULL || providerIpcData == NULL || ptr == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    os_memory_provider_t *os_provider = (os_memory_provider_t *)provider;
    if (!os_provider->IPC_enabled) {
        LOG_ERR("memory visibility mode is not UMF_MEM_MAP_SHARED")
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    os_ipc_data_t *os_ipc_data = (os_ipc_data_t *)providerIpcData;
    umf_result_t ret = UMF_RESULT_SUCCESS;
    int fd;

    if (os_ipc_data->shm_name_len) {
        fd = utils_shm_open(os_ipc_data->shm_name);
        if (fd <= 0) {
            LOG_PERR("opening a shared memory file (%s) failed",
                     os_ipc_data->shm_name);
            return UMF_RESULT_ERROR_UNKNOWN;
        }
        (void)utils_shm_unlink(os_ipc_data->shm_name);
    } else {
        umf_result_t umf_result =
            utils_duplicate_fd(os_ipc_data->pid, os_ipc_data->fd, &fd);
        if (umf_result != UMF_RESULT_SUCCESS) {
            LOG_PERR("duplicating file descriptor failed");
            return umf_result;
        }
    }

    *ptr = utils_mmap(NULL, os_ipc_data->size, os_provider->protection,
                      os_provider->visibility, fd, os_ipc_data->fd_offset);
    if (*ptr == NULL) {
        os_store_last_native_error(UMF_OS_RESULT_ERROR_ALLOC_FAILED, errno);
        LOG_PERR("memory mapping failed");
        ret = UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    (void)utils_close_fd(fd);

    return ret;
}

static umf_result_t os_close_ipc_handle(void *provider, void *ptr,
                                        size_t size) {
    if (provider == NULL || ptr == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    os_memory_provider_t *os_provider = (os_memory_provider_t *)provider;
    if (!os_provider->IPC_enabled) {
        LOG_ERR("memory visibility mode is not UMF_MEM_MAP_SHARED")
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    errno = 0;
    int ret = utils_munmap(ptr, size);
    // ignore error when size == 0
    if (ret && (size > 0)) {
        os_store_last_native_error(UMF_OS_RESULT_ERROR_FREE_FAILED, errno);
        LOG_PERR("memory unmapping failed");

        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    return UMF_RESULT_SUCCESS;
}

static umf_memory_provider_ops_t UMF_OS_MEMORY_PROVIDER_OPS = {
    .version = UMF_VERSION_CURRENT,
    .initialize = os_initialize,
    .finalize = os_finalize,
    .alloc = os_alloc,
    .get_last_native_error = os_get_last_native_error,
    .get_recommended_page_size = os_get_recommended_page_size,
    .get_min_page_size = os_get_min_page_size,
    .get_name = os_get_name,
    .ext.free = os_free,
    .ext.purge_lazy = os_purge_lazy,
    .ext.purge_force = os_purge_force,
    .ext.allocation_merge = os_allocation_merge,
    .ext.allocation_split = os_allocation_split,
    .ipc.get_ipc_handle_size = os_get_ipc_handle_size,
    .ipc.get_ipc_handle = os_get_ipc_handle,
    .ipc.put_ipc_handle = os_put_ipc_handle,
    .ipc.open_ipc_handle = os_open_ipc_handle,
    .ipc.close_ipc_handle = os_close_ipc_handle};

umf_memory_provider_ops_t *umfOsMemoryProviderOps(void) {
    return &UMF_OS_MEMORY_PROVIDER_OPS;
}

#endif // !defined(UMF_NO_HWLOC)
