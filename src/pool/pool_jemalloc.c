/*
 * Copyright (C) 2022-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base_alloc_global.h"
#include "memory_provider_internal.h"
#include "provider_tracking.h"
#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_log.h"
#include "utils_sanitizers.h"

#include <umf/memory_pool.h>
#include <umf/memory_pool_ops.h>
#include <umf/pools/pool_jemalloc.h>

#ifndef UMF_POOL_JEMALLOC_ENABLED

const umf_memory_pool_ops_t *umfJemallocPoolOps(void) { return NULL; }
umf_result_t
umfJemallocPoolParamsCreate(umf_jemalloc_pool_params_handle_t *hParams) {
    (void)hParams; // unused
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

umf_result_t
umfJemallocPoolParamsDestroy(umf_jemalloc_pool_params_handle_t hParams) {
    (void)hParams; // unused
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

umf_result_t
umfJemallocPoolParamsSetNumArenas(umf_jemalloc_pool_params_handle_t hParams,
                                  size_t numArenas) {
    (void)hParams;   // unused
    (void)numArenas; // unused
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

umf_result_t
umfJemallocPoolParamsSetName(umf_jemalloc_pool_params_handle_t hParams,
                             const char *name) {
    (void)hParams; // unused
    (void)name;    // unused
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

#else

#include <jemalloc/jemalloc.h>

#define MALLOCX_ARENA_MAX (MALLCTL_ARENAS_ALL - 1)
#define DEFAULT_NAME "jemalloc"

typedef struct umf_jemalloc_pool_params_t {
    size_t n_arenas;
    char name[64];
} umf_jemalloc_pool_params_t;

typedef struct jemalloc_memory_pool_t {
    umf_memory_provider_handle_t provider;
    size_t n_arenas;
    char name[64];
    unsigned int arena_index[];
} jemalloc_memory_pool_t;

static __TLS umf_result_t TLS_last_allocation_error;

static jemalloc_memory_pool_t *pool_by_arena_index[MALLCTL_ARENAS_ALL];

static jemalloc_memory_pool_t *get_pool_by_arena_index(unsigned arena_ind) {
    // there is no way to obtain MALLOCX_ARENA_MAX from jemalloc
    // so this checks if arena_ind does not exceed assumed range
    assert(arena_ind < MALLOCX_ARENA_MAX);

    return pool_by_arena_index[arena_ind];
}

// SplitMix64 hash
static uint64_t hash64(uint64_t x) {
    x += 0x9e3779b97f4a7c15;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9;
    x = (x ^ (x >> 27)) * 0x94d049bb133111eb;
    return x ^ (x >> 31);
}

// arena_extent_alloc - an extent allocation function conforms to the extent_alloc_t type and upon
// success returns a pointer to size bytes of mapped memory on behalf of arena arena_ind such that
// the extent's base address is a multiple of alignment, as well as setting *zero to indicate
// whether the extent is zeroed and *commit to indicate whether the extent is committed. Upon error
// the function returns NULL and leaves *zero and *commit unmodified. The size parameter is always
// a multiple of the page size. The alignment parameter is always a power of two at least as large
// as the page size. Zeroing is mandatory if *zero is true upon function entry. Committing is
// mandatory if *commit is true upon function entry. If new_addr is not NULL, the returned pointer
// must be new_addr on success or NULL on error. Committed memory may be committed in absolute
// terms as on a system that does not overcommit, or in implicit terms as on a system that
// overcommits and satisfies physical memory needs on demand via soft page faults. Note that
// replacing the default extent allocation function makes the arena's arena.<i>.dss setting irrelevant.
// (from https://jemalloc.net/jemalloc.3.html)
static void *arena_extent_alloc(extent_hooks_t *extent_hooks, void *new_addr,
                                size_t size, size_t alignment, bool *zero,
                                bool *commit, unsigned arena_ind) {
    (void)extent_hooks; // unused
    (void)arena_ind;    // unused
    umf_result_t ret;

    jemalloc_memory_pool_t *pool = get_pool_by_arena_index(arena_ind);

    void *ptr = new_addr;
    ret = umfMemoryProviderAlloc(pool->provider, size, alignment, &ptr);
    if (ret != UMF_RESULT_SUCCESS) {
        return NULL;
    }

    if (new_addr != NULL && ptr != new_addr) {
        umfMemoryProviderFree(pool->provider, ptr, size);
        return NULL;
    }

#ifndef __SANITIZE_ADDRESS__
    // jemalloc might write to new extents in realloc, so we cannot
    // mark them as inaccessible under asan
    utils_annotate_memory_inaccessible(ptr, size);
#endif

    if (*zero) {
        utils_annotate_memory_defined(ptr, size);
        memset(ptr, 0, size); // TODO: device memory is not accessible by host
    }

    *commit = true;

    return ptr;
}

// arena_extent_destroy - an extent destruction function conforms to the extent_destroy_t type and
// unconditionally destroys an extent at given addr and size with committed/decommited memory as
// indicated, on behalf of arena arena_ind. This function may be called to destroy retained extents
// during arena destruction (see arena.<i>.destroy).
// (from https://jemalloc.net/jemalloc.3.html)
static void arena_extent_destroy(extent_hooks_t *extent_hooks, void *addr,
                                 size_t size, bool committed,
                                 unsigned arena_ind) {
    (void)extent_hooks; // unused
    (void)committed;    // unused
    (void)arena_ind;    // unused

    jemalloc_memory_pool_t *pool = get_pool_by_arena_index(arena_ind);

    umf_result_t ret;
    ret = umfMemoryProviderFree(pool->provider, addr, size);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("umfMemoryProviderFree failed");
    }
}

// arena_extent_dalloc - an extent deallocation function conforms to the extent_dalloc_t type and
// deallocates an extent at given addr and size with committed/decommited memory as indicated, on
// behalf of arena arena_ind, returning false upon success. If the function returns true,
// this indicates opt-out from deallocation; the virtual memory mapping associated with the extent
// remains mapped, in the same commit state, and available for future use, in which case it will be
// automatically retained for later reuse.
// (from https://jemalloc.net/jemalloc.3.html)
static bool arena_extent_dalloc(extent_hooks_t *extent_hooks, void *addr,
                                size_t size, bool committed,
                                unsigned arena_ind) {
    (void)extent_hooks; // unused
    (void)committed;    // unused

    jemalloc_memory_pool_t *pool = get_pool_by_arena_index(arena_ind);

    umf_result_t ret;
    ret = umfMemoryProviderFree(pool->provider, addr, size);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("umfMemoryProviderFree failed in dalloc");
    }

    return ret != UMF_RESULT_SUCCESS;
}

// arena_extent_commit - an extent commit function conforms to the extent_commit_t type and commits
// zeroed physical memory to back pages within an extent at given addr and size at offset bytes,
// extending for length on behalf of arena arena_ind, returning false upon success. Committed memory
// may be committed in absolute terms as on a system that does not overcommit, or in implicit terms
// as on a system that overcommits and satisfies physical memory needs on demand via soft page faults.
// If the function returns true, this indicates insufficient physical memory to satisfy the request.
// (from https://jemalloc.net/jemalloc.3.html)
static bool arena_extent_commit(extent_hooks_t *extent_hooks, void *addr,
                                size_t size, size_t offset, size_t length,
                                unsigned arena_ind) {
    (void)extent_hooks; // unused
    (void)addr;         // unused
    (void)size;         // unused
    (void)offset;       // unused
    (void)length;       // unused
    (void)arena_ind;    // unused

    // TODO: add this function to the provider API to support Windows and USM
    return false; // false means success (commit is a nop)
}

// arena_extent_decommit - an extent decommit function conforms to the extent_decommit_t type
// and decommits any physical memory that is backing pages within an extent at given addr and size
// at offset bytes, extending for length on behalf of arena arena_ind, returning false upon success,
// in which case the pages will be committed via the extent commit function before being reused.
// If the function returns true, this indicates opt-out from decommit; the memory remains committed
// and available for future use, in which case it will be automatically retained for later reuse.
// (from https://jemalloc.net/jemalloc.3.html)
static bool arena_extent_decommit(extent_hooks_t *extent_hooks, void *addr,
                                  size_t size, size_t offset, size_t length,
                                  unsigned arena_ind) {
    (void)extent_hooks; // unused
    (void)addr;         // unused
    (void)size;         // unused
    (void)offset;       // unused
    (void)length;       // unused
    (void)arena_ind;    // unused

    // TODO: add this function to the provider API to support Windows and USM
    return true; // true means failure (unsupported)
}

// arena_extent_purge_lazy - an extent purge function conforms to the extent_purge_t type and discards
// physical pages within the virtual memory mapping associated with an extent at given addr and size
// at offset bytes, extending for length on behalf of arena arena_ind. A lazy extent purge function
// (e.g. implemented via madvise(...MADV_FREE)) can delay purging indefinitely and leave the pages
// within the purged virtual memory range in an indeterminate state, whereas a forced extent purge
// function immediately purges, and the pages within the virtual memory range will be zero-filled
// the next time they are accessed. If the function returns true, this indicates failure to purge.
// (from https://jemalloc.net/jemalloc.3.html)
static bool arena_extent_purge_lazy(extent_hooks_t *extent_hooks, void *addr,
                                    size_t size, size_t offset, size_t length,
                                    unsigned arena_ind) {
    (void)extent_hooks; // unused
    (void)size;         // unused
    (void)arena_ind;    // unused

    jemalloc_memory_pool_t *pool = get_pool_by_arena_index(arena_ind);

    umf_result_t ret = umfMemoryProviderPurgeLazy(
        pool->provider, (char *)addr + offset, length);

    return (ret != UMF_RESULT_SUCCESS); // false means success
}

// arena_extent_purge_forced - see arena_extent_purge_lazy above
static bool arena_extent_purge_forced(extent_hooks_t *extent_hooks, void *addr,
                                      size_t size, size_t offset, size_t length,
                                      unsigned arena_ind) {
    (void)extent_hooks; // unused
    (void)size;         // unused
    (void)arena_ind;    // unused

    jemalloc_memory_pool_t *pool = get_pool_by_arena_index(arena_ind);

    umf_result_t ret = umfMemoryProviderPurgeForce(
        pool->provider, (char *)addr + offset, length);

    return (ret != UMF_RESULT_SUCCESS); // false means success
}

// arena_extent_split - an extent split function conforms to the extent_split_t type and optionally
// splits an extent at given addr and size into two adjacent extents, the first of size_a bytes,
// and the second of size_b bytes, operating on committed/decommitted memory as indicated,
// on behalf of arena arena_ind, returning false upon success. If the function returns true,
// this indicates that the extent remains unsplit and therefore should continue to be operated on as a whole.
// (from https://jemalloc.net/jemalloc.3.html)
static bool arena_extent_split(extent_hooks_t *extent_hooks, void *addr,
                               size_t size, size_t size_a, size_t size_b,
                               bool committed, unsigned arena_ind) {
    (void)extent_hooks; // unused
    (void)committed;    // unused
    (void)size_b;

    assert(size_a + size_b == size);

    jemalloc_memory_pool_t *pool = get_pool_by_arena_index(arena_ind);
    assert(pool);

    umf_result_t ret =
        umfMemoryProviderAllocationSplit(pool->provider, addr, size, size_a);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("memory provider failed to split a memory region, while "
                "jemalloc requires that");
    }

    return ret != UMF_RESULT_SUCCESS;
}

// arena_extent_merge - an extent merge function conforms to the extent_merge_t type and optionally
// merges adjacent extents, at given addr_a and size_a with given addr_b and size_b into one
// contiguous extent, operating on committed/decommitted memory as indicated, on behalf of arena arena_ind,
// returning false upon success. If the function returns true, this indicates that the extents
// remain distinct mappings and therefore should continue to be operated on independently.
// (from https://jemalloc.net/jemalloc.3.html)
static bool arena_extent_merge(extent_hooks_t *extent_hooks, void *addr_a,
                               size_t size_a, void *addr_b, size_t size_b,
                               bool committed, unsigned arena_ind) {
    (void)extent_hooks; // unused
    (void)committed;    // unused

    jemalloc_memory_pool_t *pool = get_pool_by_arena_index(arena_ind);
    assert(pool);
    return umfMemoryProviderAllocationMerge(pool->provider, addr_a, addr_b,
                                            size_a + size_b) !=
           UMF_RESULT_SUCCESS;
}

// The extent_hooks_t structure comprises function pointers which are described individually below.
// jemalloc uses these functions to manage extent lifetime, which starts off with allocation
// of mapped committed memory, in the simplest case followed by deallocation. However, there are
// performance and platform reasons to retain extents for later reuse. Cleanup attempts cascade
// from deallocation to decommit to forced purging to lazy purging, which gives the extent
// management functions opportunities to reject the most permanent cleanup operations in favor
// of less permanent (and often less costly) operations. All operations except allocation can be
// universally opted out of by setting the hook pointers to NULL, or selectively opted out of
// by returning failure. Note that once the extent hook is set, the structure is accessed directly
// by the associated arenas, so it must remain valid for the entire lifetime of the arenas.
// (from https://jemalloc.net/jemalloc.3.html)
static extent_hooks_t arena_extent_hooks = {
    .alloc = arena_extent_alloc,
    .dalloc = arena_extent_dalloc,
    .destroy = arena_extent_destroy,
    .commit = arena_extent_commit,
    .decommit = arena_extent_decommit,
    .purge_lazy = arena_extent_purge_lazy,
    .purge_forced = arena_extent_purge_forced,
    .split = arena_extent_split,
    .merge = arena_extent_merge,
};

static unsigned get_arena_index(jemalloc_memory_pool_t *pool) {
    static __TLS unsigned tid = 0;

    if (tid == 0) {
        tid = utils_gettid();
    }

    return pool->arena_index[hash64(tid) % pool->n_arenas];
}

static void *op_malloc(void *pool, size_t size) {
    assert(pool);
    jemalloc_memory_pool_t *je_pool = (jemalloc_memory_pool_t *)pool;
    // MALLOCX_TCACHE_NONE is set, because jemalloc can mix objects from different arenas inside
    // the tcache, so we wouldn't be able to guarantee isolation of different providers.
    int flags = MALLOCX_ARENA(get_arena_index(je_pool)) | MALLOCX_TCACHE_NONE;
    void *ptr = je_mallocx(size, flags);
    if (ptr == NULL) {
        TLS_last_allocation_error = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        return NULL;
    }

    VALGRIND_DO_MEMPOOL_ALLOC(pool, ptr, size);

    return ptr;
}

static umf_result_t op_free(void *pool, void *ptr) {
    (void)pool; // unused
    assert(pool);

    if (ptr != NULL) {
        VALGRIND_DO_MEMPOOL_FREE(pool, ptr);
        je_dallocx(ptr, MALLOCX_TCACHE_NONE);
    }

    return UMF_RESULT_SUCCESS;
}

static void *op_calloc(void *pool, size_t num, size_t size) {
    assert(pool);
    size_t csize = num * size;
    void *ptr = op_malloc(pool, csize);
    if (ptr == NULL) {
        // TLS_last_allocation_error is set by op_malloc()
        return NULL;
    }

    utils_annotate_memory_defined(ptr, num * size);

    memset(ptr, 0, csize); // TODO: device memory is not accessible by host
    return ptr;
}

static void *op_realloc(void *pool, void *ptr, size_t size) {
    assert(pool);
    if (size == 0 && ptr != NULL) {
        je_dallocx(ptr, MALLOCX_TCACHE_NONE);
        TLS_last_allocation_error = UMF_RESULT_SUCCESS;
        VALGRIND_DO_MEMPOOL_FREE(pool, ptr);
        return NULL;
    } else if (ptr == NULL) {
        return op_malloc(pool, size);
    }

    jemalloc_memory_pool_t *je_pool = (jemalloc_memory_pool_t *)pool;
    // MALLOCX_TCACHE_NONE is set, because jemalloc can mix objects from different arenas inside
    // the tcache, so we wouldn't be able to guarantee isolation of different providers.
    int flags = MALLOCX_ARENA(get_arena_index(je_pool)) | MALLOCX_TCACHE_NONE;
    void *new_ptr = je_rallocx(ptr, size, flags);
    if (new_ptr == NULL) {
        TLS_last_allocation_error = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        return NULL;
    }

    if (new_ptr != ptr) {
        VALGRIND_DO_MEMPOOL_ALLOC(pool, new_ptr, size);
        VALGRIND_DO_MEMPOOL_FREE(pool, ptr);

        // memory was copied from old ptr so it's now defined
        utils_annotate_memory_defined(new_ptr, size);
    }

    return new_ptr;
}

static void *op_aligned_alloc(void *pool, size_t size, size_t alignment) {
    assert(pool);
    jemalloc_memory_pool_t *je_pool = (jemalloc_memory_pool_t *)pool;

    unsigned arena = get_arena_index(je_pool);
    // MALLOCX_TCACHE_NONE is set, because jemalloc can mix objects from different arenas inside
    // the tcache, so we wouldn't be able to guarantee isolation of different providers.
    int flags =
        MALLOCX_ALIGN(alignment) | MALLOCX_ARENA(arena) | MALLOCX_TCACHE_NONE;
    void *ptr = je_mallocx(size, flags);
    if (ptr == NULL) {
        TLS_last_allocation_error = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        return NULL;
    }

    VALGRIND_DO_MEMPOOL_ALLOC(pool, ptr, size);

    return ptr;
}

// Verify if the memory provider supports the split() operation,
// because jemalloc pool requires that.
static umf_result_t verify_split(umf_memory_provider_handle_t provider) {
    // Retrieve the upstream memory provider
    umf_memory_provider_handle_t upstream_provider = NULL;
    umfTrackingMemoryProviderGetUpstreamProvider(
        umfMemoryProviderGetPriv(provider), &upstream_provider);

    size_t page_size = 0;
    umf_result_t ret =
        umfMemoryProviderGetMinPageSize(upstream_provider, NULL, &page_size);
    if (ret != UMF_RESULT_SUCCESS) {
        return ret;
    }

    size_t size = 2 * page_size; // use double the page size for the split test
    if (UMF_RESULT_ERROR_NOT_SUPPORTED ==
        umfMemoryProviderAllocationSplit(upstream_provider, (void *)size, size,
                                         page_size)) {
        LOG_ERR("memory provider does not support the split operation, while "
                "jemalloc pool requires that");
        return UMF_RESULT_ERROR_NOT_SUPPORTED;
    }

    return UMF_RESULT_SUCCESS;
}

static umf_result_t op_initialize(umf_memory_provider_handle_t provider,
                                  const void *params, void **out_pool) {
    assert(provider);
    assert(out_pool);

    // Verify if the memory provider supports the split() operation,
    // because jemalloc pool requires that.
    umf_result_t ret = verify_split(provider);
    if (ret != UMF_RESULT_SUCCESS) {
        return ret;
    }

    extent_hooks_t *pHooks = &arena_extent_hooks;
    size_t unsigned_size = sizeof(unsigned);
    int n_arenas_set_from_params = 0;
    int err;
    const umf_jemalloc_pool_params_t *jemalloc_params = params;

    size_t n_arenas = 0;
    if (jemalloc_params) {
        n_arenas = jemalloc_params->n_arenas;
        n_arenas_set_from_params = 1;
    }

    if (n_arenas == 0) {
        n_arenas = utils_get_num_cores() * 4;
        if (n_arenas > MALLOCX_ARENA_MAX) {
            n_arenas = MALLOCX_ARENA_MAX;
        }
    }

    if (n_arenas > MALLOCX_ARENA_MAX) {
        LOG_ERR("Number of arenas %zu exceeds the limit (%i).", n_arenas,
                MALLOCX_ARENA_MAX);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    jemalloc_memory_pool_t *pool = umf_ba_global_alloc(
        sizeof(*pool) + n_arenas * sizeof(*pool->arena_index));
    if (!pool) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }
    memset(pool, 0, sizeof(*pool) + n_arenas * sizeof(*pool->arena_index));
    const char *pool_name = DEFAULT_NAME;
    if (jemalloc_params) {
        pool_name = jemalloc_params->name;
    }

    snprintf(pool->name, sizeof(pool->name), "%s", pool_name);

    pool->provider = provider;
    pool->n_arenas = n_arenas;

    size_t num_created = 0;
    for (size_t i = 0; i < n_arenas; i++) {
        unsigned arena_index;
        err = je_mallctl("arenas.create", (void *)&arena_index, &unsigned_size,
                         NULL, 0);
        if (err) {
            // EAGAIN - means that a memory allocation failure occurred
            // (2 * utils_get_num_cores()) is the required minimum number of arenas
            if (n_arenas_set_from_params || err != EAGAIN ||
                (i < (2 * utils_get_num_cores()))) {
                LOG_ERR("Could not create a jemalloc arena (n_arenas = %zu, i "
                        "= %zu, arena_index = %u, unsigned_size = %zu): %s",
                        n_arenas, i, arena_index, unsigned_size, strerror(err));
                goto err_cleanup;
            }

            LOG_WARN("Could not create the #%zu jemalloc arena (%s), setting "
                     "n_arenas = %zu",
                     i + 1, strerror(err), i);
            n_arenas = i;
            break;
        }

        pool->arena_index[num_created++] = arena_index;
        if (arena_index >= MALLOCX_ARENA_MAX) {
            LOG_ERR("Number of arenas exceeds the limit.");
            goto err_cleanup;
        }

        pool_by_arena_index[arena_index] = pool;

        // Setup extent_hooks for the newly created arena.
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "arena.%u.extent_hooks", arena_index);
        err = je_mallctl(cmd, NULL, NULL, (void *)&pHooks, sizeof(void *));
        if (err) {
            LOG_ERR("Could not setup extent_hooks for newly created arena.");
            goto err_cleanup;
        }
    }
    *out_pool = (umf_memory_pool_handle_t)pool;

    VALGRIND_DO_CREATE_MEMPOOL(pool, 0, 0);

    return UMF_RESULT_SUCCESS;

err_cleanup:
    // Destroy any arenas that were successfully created.
    for (size_t i = 0; i < num_created; i++) {
        char cmd[64];
        unsigned arena = pool->arena_index[i];
        snprintf(cmd, sizeof(cmd), "arena.%u.destroy", arena);
        (void)je_mallctl(cmd, NULL, 0, NULL, 0);
    }
    umf_ba_global_free(pool);
    return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
}

static umf_result_t op_finalize(void *pool) {
    assert(pool);
    umf_result_t ret = UMF_RESULT_SUCCESS;
    jemalloc_memory_pool_t *je_pool = (jemalloc_memory_pool_t *)pool;
    for (size_t i = 0; i < je_pool->n_arenas; i++) {
        char cmd[64];
        unsigned arena = je_pool->arena_index[i];
        snprintf(cmd, sizeof(cmd), "arena.%u.destroy", arena);
        if (je_mallctl(cmd, NULL, 0, NULL, 0)) {
            LOG_ERR("Could not destroy jemalloc arena %u", arena);
            ret = UMF_RESULT_ERROR_UNKNOWN;
        }
    }
    umf_ba_global_free(je_pool);

    VALGRIND_DO_DESTROY_MEMPOOL(pool);
    return ret;
}

static umf_result_t op_malloc_usable_size(void *pool, const void *ptr,
                                          size_t *size) {
    (void)pool; // not used
    if (!size) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    // Remove the 'const' qualifier because the je_malloc_usable_size
    // function requires a non-const pointer.
    *size = je_malloc_usable_size((void *)ptr);
    return UMF_RESULT_SUCCESS;
}

static umf_result_t op_get_last_allocation_error(void *pool) {
    (void)pool; // not used
    return TLS_last_allocation_error;
}

static umf_result_t op_get_name(void *pool, const char **name) {
    if (!name) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    if (pool == NULL) {
        *name = DEFAULT_NAME;
        return UMF_RESULT_SUCCESS;
    }
    jemalloc_memory_pool_t *je_pool = (jemalloc_memory_pool_t *)pool;
    *name = je_pool->name;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t op_trim_memory(void *pool, size_t minBytesToKeep) {
    // there is no way to tell jemalloc to keep a minimum number of bytes
    // so we just purge all arenas
    if (minBytesToKeep > 0) {
        LOG_WARN("Ignoring minBytesToKeep (%zu) in jemalloc pool",
                 minBytesToKeep);
    }

    jemalloc_memory_pool_t *je_pool = (jemalloc_memory_pool_t *)pool;
    for (size_t i = 0; i < je_pool->n_arenas; i++) {
        char cmd[64];
        unsigned arena = je_pool->arena_index[i];
        snprintf(cmd, sizeof(cmd), "arena.%u.purge", arena);
        if (je_mallctl(cmd, NULL, NULL, NULL, 0)) {
            LOG_ERR("Could not purge jemalloc arena %u", arena);
            return UMF_RESULT_ERROR_UNKNOWN;
        }
    }

    return UMF_RESULT_SUCCESS;
}

static umf_memory_pool_ops_t UMF_JEMALLOC_POOL_OPS = {
    .version = UMF_POOL_OPS_VERSION_CURRENT,
    .initialize = op_initialize,
    .finalize = op_finalize,
    .malloc = op_malloc,
    .calloc = op_calloc,
    .realloc = op_realloc,
    .aligned_malloc = op_aligned_alloc,
    .malloc_usable_size = op_malloc_usable_size,
    .free = op_free,
    .get_last_allocation_error = op_get_last_allocation_error,
    .get_name = op_get_name,
    .ext_trim_memory = op_trim_memory,
};

const umf_memory_pool_ops_t *umfJemallocPoolOps(void) {
    return &UMF_JEMALLOC_POOL_OPS;
}

umf_result_t
umfJemallocPoolParamsCreate(umf_jemalloc_pool_params_handle_t *hParams) {
    umf_jemalloc_pool_params_t *params = umf_ba_global_alloc(sizeof(*params));
    if (!params) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }
    memset(params, 0, sizeof(*params));
    strncpy(params->name, DEFAULT_NAME, sizeof(params->name) - 1);
    params->name[sizeof(params->name) - 1] = '\0';
    *hParams = params;
    return UMF_RESULT_SUCCESS;
}

umf_result_t
umfJemallocPoolParamsDestroy(umf_jemalloc_pool_params_handle_t hParams) {
    umf_ba_global_free(hParams);
    return UMF_RESULT_SUCCESS;
}

umf_result_t
umfJemallocPoolParamsSetNumArenas(umf_jemalloc_pool_params_handle_t hParams,
                                  size_t numArenas) {
    if (!hParams) {
        LOG_ERR("jemalloc pool params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    hParams->n_arenas = numArenas;
    return UMF_RESULT_SUCCESS;
}

umf_result_t
umfJemallocPoolParamsSetName(umf_jemalloc_pool_params_handle_t hParams,
                             const char *name) {
    if (!hParams) {
        LOG_ERR("jemalloc pool params handle is NULL");
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

#endif /* UMF_POOL_JEMALLOC_ENABLED */
