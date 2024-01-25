/*
 * Copyright (C) 2022-2023 Intel Corporation
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

#include "provider_os_memory_internal.h"
#include <umf.h>
#include <umf/memory_provider_ops.h>
#include <umf/providers/provider_os_memory.h>

typedef struct umf_os_memory_provider_config_t {
    unsigned protection; // combination of OS-specific protection flags
    unsigned visibility;

    // NUMA config
    unsigned long *nodemask;
    unsigned long maxnode;
    unsigned numa_mode;
    unsigned numa_flags; // combination of OS-specific NUMA flags

    // others
    int traces; // log level of debug traces
} umf_os_memory_provider_config_t;

typedef struct os_memory_provider_t {
    unsigned protection; // combination of OS-specific protection flags
    unsigned visibility;

    // NUMA config
    hwloc_bitmap_t nodeset;
    hwloc_membind_policy_t numa_policy;
    int numa_flags; // combination of hwloc flags

    // others
    int traces; // log level of debug traces

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

static const char *Native_error_str[] = {
    [_UMF_OS_RESULT_SUCCESS] = "success",
    [_UMF_OS_RESULT_ERROR_ALLOC_FAILED] = "memory allocation failed",
    [_UMF_OS_RESULT_ERROR_ADDRESS_NOT_ALIGNED] =
        "allocated address is not aligned",
    [_UMF_OS_RESULT_ERROR_BIND_FAILED] = "binding memory to NUMA node failed",
    [_UMF_OS_RESULT_ERROR_FREE_FAILED] = "memory deallocation failed",
    [_UMF_OS_RESULT_ERROR_PURGE_LAZY_FAILED] = "lazy purging failed",
    [_UMF_OS_RESULT_ERROR_PURGE_FORCE_FAILED] = "force purging failed",
};

static void os_store_last_native_error(int32_t native_error, int errno_value) {
    TLS_last_native_error.native_error = native_error;
    TLS_last_native_error.errno_value = errno_value;
}

static umf_result_t nodemask_to_hwloc_nodeset(const unsigned long *nodemask,
                                              unsigned long maxnode,
                                              hwloc_bitmap_t *out_nodeset) {
    if (out_nodeset == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (maxnode > UINT_MAX) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *out_nodeset = hwloc_bitmap_alloc();
    if (!*out_nodeset) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    if (maxnode == 0 || nodemask == NULL) {
        return UMF_RESULT_SUCCESS;
    }

    unsigned bits_per_mask = sizeof(unsigned long) * 8;
    hwloc_bitmap_from_ulongs(
        *out_nodeset, (maxnode + bits_per_mask - 1) / bits_per_mask, nodemask);

    return UMF_RESULT_SUCCESS;
}

int os_translate_flags(unsigned in_flags, unsigned max,
                       int (*translate_flag)(unsigned)) {
    unsigned out_flags = 0;
    for (unsigned n = 1; n < max; n <<= 1) {
        if (in_flags & n) {
            int f = translate_flag(n);
            if (f < 0) {
                return -1;
            }
            out_flags |= (unsigned)f;
            in_flags &= ~n; // clear this bit
        }
    }

    if (in_flags != 0) {
        return -1;
    }

    return out_flags;
}

static hwloc_membind_policy_t translate_numa_mode(umf_numa_mode_t mode,
                                                  int nodemaskEmpty) {
    switch (mode) {
    case UMF_NUMA_MODE_DEFAULT:
        if (!nodemaskEmpty) {
            // nodeset must be empty
            return -1;
        }
        return HWLOC_MEMBIND_DEFAULT;
    case UMF_NUMA_MODE_BIND:
        return HWLOC_MEMBIND_BIND;
    case UMF_NUMA_MODE_INTERLEAVE:
        return HWLOC_MEMBIND_INTERLEAVE;
    case UMF_NUMA_MODE_PREFERRED:
        return HWLOC_MEMBIND_BIND;
    case UMF_NUMA_MODE_LOCAL:
        if (!nodemaskEmpty) {
            // nodeset must be empty
            return -1;
        }
        return HWLOC_MEMBIND_BIND;
    case UMF_NUMA_MODE_STATIC_NODES: // unsupported
        // MPOL_F_STATIC_NODES is undefined
        return -1;
    case UMF_NUMA_MODE_RELATIVE_NODES: // unsupported
        // MPOL_F_RELATIVE_NODES is undefined
        return -1;
    }
    return -1;
}

static int translate_one_numa_flag(unsigned numa_flag) {
    switch (numa_flag) {
    case UMF_NUMA_FLAGS_STRICT:
        return HWLOC_MEMBIND_STRICT;
    case UMF_NUMA_FLAGS_MOVE:
        return HWLOC_MEMBIND_MIGRATE;
    case UMF_NUMA_FLAGS_MOVE_ALL:
        return -1; /* unsupported */
    }
    return -1;
}

static int translate_numa_flags(unsigned numa_flags, umf_numa_mode_t mode) {
    // translate numa_flags - combination of 'umf_numa_flags_t' flags
    int flags = os_translate_flags(numa_flags, UMF_NUMA_FLAGS_MAX,
                                   translate_one_numa_flag);
    if (mode == UMF_NUMA_MODE_BIND) {
        /* HWLOC uses MPOL_PREFERRED[_MANY] unless HWLOC_MEMBIND_STRICT is specified */
        flags |= HWLOC_MEMBIND_STRICT;
    }
    /* UMF always operates on NUMA nodes */
    return flags | HWLOC_MEMBIND_BYNODESET;
}

static umf_result_t translate_params(umf_os_memory_provider_params_t *in_params,
                                     os_memory_provider_t *provider) {
    int ret;

    // log level of debug traces
    provider->traces = in_params->traces;

    ret = os_translate_mem_protection_flags(in_params->protection);
    if (ret < 0) {
        if (in_params->traces) {
            fprintf(stderr, "error: incorrect memory protection flags: %u\n",
                    in_params->protection);
        }
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    provider->protection = ret;

    ret = os_translate_mem_visibility(in_params->visibility);
    if (ret < 0) {
        if (in_params->traces) {
            fprintf(stderr, "error: incorrect memory visibility mode: %u\n",
                    in_params->visibility);
        }
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    provider->visibility = ret;

    // NUMA config
    int emptyNodeset = (!in_params->maxnode || !in_params->nodemask);
    ret = translate_numa_mode(in_params->numa_mode, emptyNodeset);
    if (ret < 0) {
        if (in_params->traces) {
            fprintf(stderr, "error: incorrect NUMA mode: %u\n",
                    in_params->numa_mode);
        }
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    provider->numa_policy = ret;

    ret = translate_numa_flags(in_params->numa_flags, in_params->numa_mode);
    if (ret < 0) {
        if (in_params->traces) {
            fprintf(stderr, "error: incorrect NUMA flags: %u\n",
                    in_params->numa_flags);
        }
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    provider->numa_flags = ret;

    return nodemask_to_hwloc_nodeset(in_params->nodemask, in_params->maxnode,
                                     &provider->nodeset);
}

static umf_result_t os_initialize(void *params, void **provider) {
    umf_result_t ret;

    if (provider == NULL || params == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_os_memory_provider_params_t *in_params =
        (umf_os_memory_provider_params_t *)params;

    if (in_params->visibility == UMF_VISIBILITY_SHARED &&
        in_params->numa_mode != UMF_NUMA_MODE_DEFAULT) {
        // TODO: add support for that
        if (in_params->traces) {
            fprintf(stderr,
                    "NUMA binding mode (%i) not supported for "
                    "UMF_VISIBILITY_SHARED\n",
                    in_params->numa_mode);
        }
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    os_memory_provider_t *os_provider =
        (os_memory_provider_t *)calloc(1, sizeof(os_memory_provider_t));
    if (!os_provider) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    int r = hwloc_topology_init(&os_provider->topo);
    if (r) {
        if (os_provider->traces) {
            fprintf(stderr, "HWLOC topology init failed\n");
        }
        free(os_provider);
    }

    r = hwloc_topology_load(os_provider->topo);
    if (r) {
        if (os_provider->traces) {
            fprintf(stderr, "HWLOC topology discovery failed\n");
        }
        hwloc_topology_destroy(os_provider->topo);
        free(os_provider);
    }

    ret = translate_params(in_params, os_provider);
    if (ret != UMF_RESULT_SUCCESS) {
        hwloc_topology_destroy(os_provider->topo);
        free(os_provider);
        return ret;
    }

    if (os_provider->traces) {
        char *strp = NULL;
        hwloc_bitmap_list_asprintf(&strp, os_provider->nodeset);

        if (strp) {
            printf("OS provider initialized with NUMA nodes: %s\n", strp);
        }

        free(strp);
    }

    *provider = os_provider;

    return UMF_RESULT_SUCCESS;
}

static void os_finalize(void *provider) {
    if (provider == NULL) {
        assert(0);
        return;
    }

    os_memory_provider_t *os_provider = provider;
    hwloc_bitmap_free(os_provider->nodeset);
    hwloc_topology_destroy(os_provider->topo);
    free(os_provider);
}

static umf_result_t os_get_min_page_size(void *provider, void *ptr,
                                         size_t *page_size);

static void print_numa_nodes(os_memory_provider_t *os_provider, void *addr,
                             size_t size) {
    hwloc_bitmap_t nodeset = hwloc_bitmap_alloc();
    if (!nodeset) {
        fprintf(stderr,
                "cannot print assigned NUMA node due to allocation failure\n");
    } else {
        int ret = hwloc_get_area_memlocation(os_provider->topo, addr, 1,
                                             nodeset, HWLOC_MEMBIND_BYNODESET);
        if (ret) {
            fprintf(stderr, "cannot print assigned NUMA node (errno = %i)\n",
                    errno);
            perror("get_mempolicy()");
        } else {
            char *strp = NULL;
            hwloc_bitmap_list_asprintf(&strp, nodeset);

            if (!strp) {
                fprintf(stderr, "cannot print assigned NUMA node due to "
                                "allocation failure\n");
            } else {
                printf("alloc(%zu) = 0x%llx, allocate on NUMA nodes = %s\n",
                       size, (unsigned long long)addr, strp);
            }
            free(strp);
        }
    }

    hwloc_bitmap_free(nodeset);
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
        if (os_provider->traces) {
            fprintf(stderr,
                    "wrong alignment: %zu (not a multiple or a divider of the "
                    "minimum page size (%zu))\n",
                    alignment, page_size);
        }
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    int flags = os_provider->visibility;
    int protection = os_provider->protection;

    void *addr = NULL;
    errno = 0;
    ret = os_mmap_aligned(NULL, size, alignment, page_size, protection, flags,
                          -1, 0, &addr);
    if (ret) {
        os_store_last_native_error(UMF_OS_RESULT_ERROR_ALLOC_FAILED, errno);
        if (os_provider->traces) {
            perror("memory allocation failed");
        }
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    // verify the alignment
    if ((alignment > 0) && ((uintptr_t)addr % alignment)) {
        if (os_provider->traces) {
            os_store_last_native_error(UMF_OS_RESULT_ERROR_ADDRESS_NOT_ALIGNED,
                                       0);
            fprintf(stderr,
                    "allocated address 0x%llx is not aligned to %zu (0x%zx) "
                    "bytes\n",
                    (unsigned long long)addr, alignment, alignment);
        }
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
        if (os_provider->traces) {
            perror("binding memory to NUMA node failed");
        }
        if (errno != ENOSYS) { // ENOSYS - Function not implemented
            // Do not error out if memory binding is not implemented at all (like in case of WSL on Windows).
            goto err_unmap;
        }
    }

    if (os_provider->traces) {
        // TODO: if we don't touch the page, we'll get EFAULT from move_pages.
        // Should we add an option to touch pages after the allocation?
        print_numa_nodes(os_provider, addr, size);
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

    errno = 0;
    int ret = os_munmap(ptr, size);
    // ignore error when size == 0
    if (ret && (size > 0)) {
        os_store_last_native_error(UMF_OS_RESULT_ERROR_FREE_FAILED, errno);
        if (os_provider->traces) {
            perror("memory deallocation failed");
        }
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

    os_memory_provider_t *os_provider = (os_memory_provider_t *)provider;

    errno = 0;
    if (os_purge(ptr, size, UMF_PURGE_LAZY)) {
        os_store_last_native_error(UMF_OS_RESULT_ERROR_PURGE_LAZY_FAILED,
                                   errno);
        if (os_provider->traces) {
            perror("lazy purging failed");
        }
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }
    return UMF_RESULT_SUCCESS;
}

static umf_result_t os_purge_force(void *provider, void *ptr, size_t size) {
    if (provider == NULL || ptr == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    os_memory_provider_t *os_provider = (os_memory_provider_t *)provider;

    errno = 0;
    if (os_purge(ptr, size, UMF_PURGE_FORCE)) {
        os_store_last_native_error(UMF_OS_RESULT_ERROR_PURGE_FORCE_FAILED,
                                   errno);
        if (os_provider->traces) {
            perror("force purging failed");
        }
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
    (void)provider;
    (void)ptr;
    (void)totalSize;
    (void)firstSize;
    // nop
    return UMF_RESULT_SUCCESS;
}

static umf_result_t os_allocation_merge(void *provider, void *lowPtr,
                                        void *highPtr, size_t totalSize) {
    (void)provider;
    (void)lowPtr;
    (void)highPtr;
    (void)totalSize;
    // nop
    return UMF_RESULT_SUCCESS;
}

umf_memory_provider_ops_t UMF_OS_MEMORY_PROVIDER_OPS = {
    .version = UMF_VERSION_CURRENT,
    .initialize = os_initialize,
    .finalize = os_finalize,
    .alloc = os_alloc,
    .free = os_free,
    .get_last_native_error = os_get_last_native_error,
    .get_recommended_page_size = os_get_recommended_page_size,
    .get_min_page_size = os_get_min_page_size,
    .purge_lazy = os_purge_lazy,
    .purge_force = os_purge_force,
    .get_name = os_get_name,
    .allocation_split = os_allocation_split,
    .allocation_merge = os_allocation_merge};
