/*
 * Copyright (C) 2022-2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include <jemalloc/jemalloc.h>

#include "utils_common.h"
#include <umf/memory_pool.h>
#include <umf/memory_pool_ops.h>
#include <umf/pools/pool_jemalloc.h>

#define MALLOCX_ARENA_MAX (MALLCTL_ARENAS_ALL - 1)

typedef struct jemalloc_memory_pool_t {
    umf_memory_provider_handle_t provider;
    unsigned int arena_index; // index of jemalloc arena
} jemalloc_memory_pool_t;

static __TLS umf_result_t TLS_last_allocation_error;

static jemalloc_memory_pool_t *pool_by_arena_index[MALLCTL_ARENAS_ALL];

static jemalloc_memory_pool_t *get_pool_by_arena_index(unsigned arena_ind) {
    // there is no way to obtain MALLOCX_ARENA_MAX from jemalloc
    // so this checks if arena_ind does not exceed assumed range
    assert(arena_ind < MALLOCX_ARENA_MAX);

    return pool_by_arena_index[arena_ind];
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

    if (*zero) {
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
        fprintf(stderr, "umfMemoryProviderFree failed \n");
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
    (void)addr;         // unused
    (void)size;         // unused
    (void)committed;    // unused
    (void)arena_ind;    // unused

    return true; // true means failure (unsupported)
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
// within the purged virtual memory range in an indeterminite state, whereas a forced extent purge
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
    return umfMemoryProviderAllocationSplit(pool->provider, addr, size,
                                            size_a) != UMF_RESULT_SUCCESS;
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

static void *je_malloc(void *pool, size_t size) {
    assert(pool);
    jemalloc_memory_pool_t *je_pool = (jemalloc_memory_pool_t *)pool;
    // MALLOCX_TCACHE_NONE is set, because jemalloc can mix objects from different arenas inside
    // the tcache, so we wouldn't be able to guarantee isolation of different providers.
    int flags = MALLOCX_ARENA(je_pool->arena_index) | MALLOCX_TCACHE_NONE;
    void *ptr = mallocx(size, flags);
    if (ptr == NULL) {
        TLS_last_allocation_error = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        return NULL;
    }

    return ptr;
}

static umf_result_t je_free(void *pool, void *ptr) {
    (void)pool; // unused
    assert(pool);

    if (ptr != NULL) {
        dallocx(ptr, MALLOCX_TCACHE_NONE);
    }

    return UMF_RESULT_SUCCESS;
}

static void *je_calloc(void *pool, size_t num, size_t size) {
    assert(pool);
    size_t csize = num * size;
    void *ptr = je_malloc(pool, csize);
    if (ptr == NULL) {
        // TLS_last_allocation_error is set by je_malloc()
        return NULL;
    }

    memset(ptr, 0, csize); // TODO: device memory is not accessible by host
    return ptr;
}

static void *je_realloc(void *pool, void *ptr, size_t size) {
    assert(pool);
    if (size == 0 && ptr != NULL) {
        dallocx(ptr, MALLOCX_TCACHE_NONE);
        TLS_last_allocation_error = UMF_RESULT_SUCCESS;
        return NULL;
    } else if (ptr == NULL) {
        return je_malloc(pool, size);
    }

    jemalloc_memory_pool_t *je_pool = (jemalloc_memory_pool_t *)pool;
    // MALLOCX_TCACHE_NONE is set, because jemalloc can mix objects from different arenas inside
    // the tcache, so we wouldn't be able to guarantee isolation of different providers.
    int flags = MALLOCX_ARENA(je_pool->arena_index) | MALLOCX_TCACHE_NONE;
    void *new_ptr = rallocx(ptr, size, flags);
    if (new_ptr == NULL) {
        TLS_last_allocation_error = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        return NULL;
    }

    return new_ptr;
}

static void *je_aligned_alloc(void *pool, size_t size, size_t alignment) {
    assert(pool);
    jemalloc_memory_pool_t *je_pool = (jemalloc_memory_pool_t *)pool;
    unsigned arena = je_pool->arena_index;
    // MALLOCX_TCACHE_NONE is set, because jemalloc can mix objects from different arenas inside
    // the tcache, so we wouldn't be able to guarantee isolation of different providers.
    int flags =
        MALLOCX_ALIGN(alignment) | MALLOCX_ARENA(arena) | MALLOCX_TCACHE_NONE;
    void *ptr = mallocx(size, flags);
    if (ptr == NULL) {
        TLS_last_allocation_error = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        return NULL;
    }

    return ptr;
}

static umf_result_t je_initialize(umf_memory_provider_handle_t provider,
                                  void *params, void **out_pool) {
    assert(provider);
    assert(out_pool);
    (void)params; // unused

    extent_hooks_t *pHooks = &arena_extent_hooks;
    size_t unsigned_size = sizeof(unsigned);
    int err;

    jemalloc_memory_pool_t *pool = malloc(sizeof(jemalloc_memory_pool_t));
    if (!pool) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    pool->provider = provider;

    unsigned arena_index;
    err =
        mallctl("arenas.create", (void *)&arena_index, &unsigned_size, NULL, 0);
    if (err) {
        fprintf(stderr, "Could not create arena.\n");
        goto err_free_pool;
    }

    // setup extent_hooks for newly created arena
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "arena.%u.extent_hooks", arena_index);
    err = mallctl(cmd, NULL, NULL, (void *)&pHooks, sizeof(void *));
    if (err) {
        snprintf(cmd, sizeof(cmd), "arena.%u.destroy", arena_index);
        mallctl(cmd, NULL, 0, NULL, 0);
        fprintf(stderr,
                "Could not setup extent_hooks for newly created arena.\n");
        goto err_free_pool;
    }

    pool->arena_index = arena_index;
    pool_by_arena_index[arena_index] = pool;

    *out_pool = (umf_memory_pool_handle_t)pool;

    return UMF_RESULT_SUCCESS;

err_free_pool:
    free(pool);
    return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
}

static void je_finalize(void *pool) {
    assert(pool);
    jemalloc_memory_pool_t *je_pool = (jemalloc_memory_pool_t *)pool;
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "arena.%u.destroy", je_pool->arena_index);
    mallctl(cmd, NULL, 0, NULL, 0);
    pool_by_arena_index[je_pool->arena_index] = NULL;
    free(je_pool);
}

static size_t je_malloc_usable_size(void *pool, void *ptr) {
    (void)pool; // not used
    return malloc_usable_size(ptr);
}

static umf_result_t je_get_last_allocation_error(void *pool) {
    (void)pool; // not used
    return TLS_last_allocation_error;
}

umf_memory_pool_ops_t UMF_JEMALLOC_POOL_OPS = {
    .version = UMF_VERSION_CURRENT,
    .initialize = je_initialize,
    .finalize = je_finalize,
    .malloc = je_malloc,
    .calloc = je_calloc,
    .realloc = je_realloc,
    .aligned_malloc = je_aligned_alloc,
    .malloc_usable_size = je_malloc_usable_size,
    .free = je_free,
    .get_last_allocation_error = je_get_last_allocation_error,
};
