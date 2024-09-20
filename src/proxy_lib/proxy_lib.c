/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

/*
 * UMF proxy library - a library for intercepting user allocation requests
 *
 * It intercepts following APIs:
 * - aligned_alloc()
 * - calloc()
 * - free()
 * - malloc()
 * - malloc_usable_size() for Linux or _msize() for Windows
 * - realloc()
 *
 * Additionally for Windows only:
 * - _aligned_malloc()
 * - _aligned_realloc()
 * - _aligned_recalloc()
 * - _aligned_msize()
 * - _aligned_free()
 * - _aligned_offset_malloc()
 * - _aligned_offset_realloc()
 * - _aligned_offset_recalloc()
 */

#if (defined PROXY_LIB_USES_JEMALLOC_POOL)
#include <umf/pools/pool_jemalloc.h>
#define umfPoolManagerOps umfJemallocPoolOps
#elif (defined PROXY_LIB_USES_SCALABLE_POOL)
#include <umf/pools/pool_scalable.h>
#define umfPoolManagerOps umfScalablePoolOps
#else
#error Pool manager not defined
#endif

#include <assert.h>
#include <limits.h>
#include <stdio.h>

#include <umf/memory_pool.h>
#include <umf/memory_provider.h>
#include <umf/providers/provider_os_memory.h>

#include "base_alloc_linear.h"
#include "proxy_lib.h"
#include "utils_common.h"
#include "utils_log.h"

#ifdef _WIN32 /* Windows ***************************************/

#define _X86_
#include <process.h>
#include <synchapi.h>

#define UTIL_ONCE_FLAG INIT_ONCE
#define UTIL_ONCE_FLAG_INIT INIT_ONCE_STATIC_INIT

void utils_init_once(UTIL_ONCE_FLAG *flag, void (*onceCb)(void));

#else /* Linux *************************************************/

#include <stdlib.h>
#include <string.h>

#include "utils_concurrency.h"

#endif /* _WIN32 ***********************************************/

/*
 * The UMF proxy library uses two memory allocators:
 * 1) the "LEAK" internal linear base allocator based on the anonymous mapped
 *    memory that will NOT be destroyed (with API ba_leak_*()).
 * 2) the main one - UMF pool allocator.
 *
 * Ad 1)
 * The "LEAK" internal linear base allocator is used from the very beginning
 * to the creation of a UMF pool in the constructor of the proxy library.
 * It is used to allocate memory for OS specific data used during loading and unloading
 * applications (for example _dl_init() and _dl_fini() on Linux storing data of all
 * constructors and destructors that have to be called) and also memory needed
 * by umfMemoryProviderCreate() and umfPoolCreate().
 * That memory will be leaked on purpose (OS will have to free it during destroying
 * the process), because we cannot free the memory containing data of destructors
 * that have to be called at the end (for example memory allocated by _dl_init()
 * and used internally by _dl_fini() on Linux).
 * The "LEAK" internal linear base allocator uses about 900 kB on Linux.
 *
 * Ad 2)
 * The UMF pool allocator (the main one) is used from the creation to the destruction
 * of a UMF pool to allocate memory needed by an application. It should be freed
 * by an application.
 */

static UTIL_ONCE_FLAG Base_alloc_leak_initialized = UTIL_ONCE_FLAG_INIT;
static umf_ba_linear_pool_t *Base_alloc_leak = NULL;
static umf_memory_provider_handle_t OS_memory_provider = NULL;
static umf_memory_pool_handle_t Proxy_pool = NULL;

// it protects us from recursion in umfPool*()
static __TLS int was_called_from_umfPool = 0;

/*****************************************************************************/
/*** The constructor and destructor of the proxy library *********************/
/*****************************************************************************/

void proxy_lib_create_common(void) {
    utils_log_init();
    umf_os_memory_provider_params_t os_params =
        umfOsMemoryProviderParamsDefault();
    umf_result_t umf_result;

#ifndef _WIN32
    char shm_name[NAME_MAX];

    if (utils_env_var_has_str("UMF_PROXY", "page.disposition=shared-fd")) {
        LOG_DEBUG("proxy_lib: using the MAP_SHARED visibility mode with the "
                  "file descriptor duplication");
        os_params.visibility = UMF_MEM_MAP_SHARED;
        os_params.shm_name = NULL;

    } else if (utils_env_var_has_str("UMF_PROXY",
                                     "page.disposition=shared-shm")) {
        LOG_DEBUG("proxy_lib: using the MAP_SHARED visibility mode with the "
                  "named shared memory");
        os_params.visibility = UMF_MEM_MAP_SHARED;

        memset(shm_name, 0, NAME_MAX);
        sprintf(shm_name, "umf_proxy_lib_shm_pid_%i", utils_getpid());
        os_params.shm_name = shm_name;

        LOG_DEBUG("proxy_lib: using the MAP_SHARED visibility mode with the "
                  "named shared memory: %s",
                  os_params.shm_name);
    }
#endif

    umf_result = umfMemoryProviderCreate(umfOsMemoryProviderOps(), &os_params,
                                         &OS_memory_provider);
    if (umf_result != UMF_RESULT_SUCCESS) {
        LOG_ERR("creating OS memory provider failed");
        exit(-1);
    }

    umf_result =
        umfPoolCreate(umfPoolManagerOps(), OS_memory_provider, NULL,
                      UMF_POOL_CREATE_FLAG_DISABLE_TRACKING, &Proxy_pool);
    if (umf_result != UMF_RESULT_SUCCESS) {
        LOG_ERR("creating UMF pool manager failed");
        exit(-1);
    }
    // The UMF pool has just been created (Proxy_pool != NULL). Stop using
    // the linear allocator and start using the UMF pool allocator from now on.
}

void proxy_lib_destroy_common(void) {
    if (utils_is_running_in_proxy_lib()) {
        // We cannot destroy 'Base_alloc_leak' nor 'Proxy_pool' nor 'OS_memory_provider',
        // because it could lead to use-after-free in the program's unloader
        // (for example _dl_fini() on Linux).
        return;
    }

    umf_memory_pool_handle_t pool = Proxy_pool;
    Proxy_pool = NULL;
    umfPoolDestroy(pool);

    umf_memory_provider_handle_t provider = OS_memory_provider;
    OS_memory_provider = NULL;
    umfMemoryProviderDestroy(provider);
}

/*****************************************************************************/
/*** Generic version of realloc() of linear base allocator *******************/
/*****************************************************************************/

static inline void *ba_generic_realloc(umf_ba_linear_pool_t *pool, void *ptr,
                                       size_t new_size, size_t max_size) {
    assert(ptr);      // it should be verified in the main realloc()
    assert(new_size); // it should be verified in the main realloc()
    assert(max_size); // max_size should be set in the main realloc()

    void *new_ptr = umf_ba_linear_alloc(pool, new_size);
    if (!new_ptr) {
        return NULL;
    }

    if (new_size > max_size) {
        new_size = max_size;
    }

    memcpy(new_ptr, ptr, new_size);

    // we can free the old ptr now
    umf_ba_linear_free(pool, ptr);

    return new_ptr;
}

/*****************************************************************************/
/*** The "LEAK" linear base allocator functions ******************************/
/*****************************************************************************/

static void ba_leak_create(void) { Base_alloc_leak = umf_ba_linear_create(0); }

// it does not implement destroy(), because we cannot destroy non-freed memory

static void ba_leak_init_once(void) {
    utils_init_once(&Base_alloc_leak_initialized, ba_leak_create);
}

static inline void *ba_leak_malloc(size_t size) {
    ba_leak_init_once();
    return umf_ba_linear_alloc(Base_alloc_leak, size);
}

static inline void *ba_leak_calloc(size_t nmemb, size_t size) {
    ba_leak_init_once();
    // umf_ba_linear_alloc() returns zeroed memory
    return umf_ba_linear_alloc(Base_alloc_leak, nmemb * size);
}

static inline void *ba_leak_realloc(void *ptr, size_t size, size_t max_size) {
    ba_leak_init_once();
    return ba_generic_realloc(Base_alloc_leak, ptr, size, max_size);
}

static inline void *ba_leak_aligned_alloc(size_t alignment, size_t size) {
    ba_leak_init_once();
    void *ptr = umf_ba_linear_alloc(Base_alloc_leak, size + alignment);
    return (void *)ALIGN_UP((uintptr_t)ptr, alignment);
}

static inline int ba_leak_free(void *ptr) {
    ba_leak_init_once();
    return umf_ba_linear_free(Base_alloc_leak, ptr);
}

static inline size_t ba_leak_pool_contains_pointer(void *ptr) {
    ba_leak_init_once();
    return umf_ba_linear_pool_contains_pointer(Base_alloc_leak, ptr);
}

/*****************************************************************************/
/*** The UMF pool allocator functions (the public API) ***********************/
/*****************************************************************************/

void *malloc(size_t size) {
    if (!was_called_from_umfPool && Proxy_pool) {
        was_called_from_umfPool = 1;
        void *ptr = umfPoolMalloc(Proxy_pool, size);
        was_called_from_umfPool = 0;
        return ptr;
    }

    return ba_leak_malloc(size);
}

void *calloc(size_t nmemb, size_t size) {
    if (!was_called_from_umfPool && Proxy_pool) {
        was_called_from_umfPool = 1;
        void *ptr = umfPoolCalloc(Proxy_pool, nmemb, size);
        was_called_from_umfPool = 0;
        return ptr;
    }

    return ba_leak_calloc(nmemb, size);
}

void free(void *ptr) {
    if (ptr == NULL) {
        return;
    }

    if (ba_leak_free(ptr) == 0) {
        return;
    }

    if (Proxy_pool) {
        if (umfPoolFree(Proxy_pool, ptr) != UMF_RESULT_SUCCESS) {
            LOG_ERR("umfPoolFree() failed");
            assert(0);
        }
        return;
    }

    assert(0);
    return;
}

void *realloc(void *ptr, size_t size) {
    if (ptr == NULL) {
        return malloc(size);
    }

    if (size == 0) {
        free(ptr);
        return NULL;
    }

    size_t leak_pool_contains_pointer = ba_leak_pool_contains_pointer(ptr);
    if (leak_pool_contains_pointer) {
        return ba_leak_realloc(ptr, size, leak_pool_contains_pointer);
    }

    if (Proxy_pool) {
        was_called_from_umfPool = 1;
        void *new_ptr = umfPoolRealloc(Proxy_pool, ptr, size);
        was_called_from_umfPool = 0;
        return new_ptr;
    }

    assert(0);
    return NULL;
}

void *aligned_alloc(size_t alignment, size_t size) {
    if (!was_called_from_umfPool && Proxy_pool) {
        was_called_from_umfPool = 1;
        void *ptr = umfPoolAlignedMalloc(Proxy_pool, size, alignment);
        was_called_from_umfPool = 0;
        return ptr;
    }

    return ba_leak_aligned_alloc(alignment, size);
}

#ifdef _WIN32
size_t _msize(void *ptr) {
#else
size_t malloc_usable_size(void *ptr) {
#endif

    // a check to verify we are running the proxy library
    if (ptr == (void *)0x01) {
        return 0xDEADBEEF;
    }

    if (!was_called_from_umfPool && Proxy_pool) {
        was_called_from_umfPool = 1;
        size_t size = umfPoolMallocUsableSize(Proxy_pool, ptr);
        was_called_from_umfPool = 0;
        return size;
    }

    return 0; // unsupported in this case
}

// Add Microsoft aligned variants
#ifdef _WIN32

void *_aligned_malloc(size_t size, size_t alignment) {
    return aligned_alloc(alignment, size);
}

void *_aligned_realloc(void *ptr, size_t size, size_t alignment) {
    if (alignment == 0) {
        return realloc(ptr, size);
    }
    return NULL; // not supported in this case
}

void *_aligned_recalloc(void *ptr, size_t num, size_t size, size_t alignment) {
    (void)ptr;       // unused
    (void)num;       // unused
    (void)size;      // unused
    (void)alignment; // unused
    return NULL;     // not supported
}

size_t _aligned_msize(void *ptr, size_t alignment, size_t offset) {
    (void)alignment; // unused
    (void)offset;    // unused
    return _msize(ptr);
}

void _aligned_free(void *ptr) { free(ptr); }

void *_aligned_offset_malloc(size_t size, size_t alignment, size_t offset) {
    if (offset == 0) {
        return aligned_alloc(alignment, size);
    }
    return NULL; // not supported in this case
}

void *_aligned_offset_realloc(void *ptr, size_t size, size_t alignment,
                              size_t offset) {
    if (alignment == 0 && offset == 0) {
        return realloc(ptr, size);
    }
    return NULL; // not supported in this case
}

void *_aligned_offset_recalloc(void *ptr, size_t num, size_t size,
                               size_t alignment, size_t offset) {
    (void)ptr;       // unused
    (void)num;       // unused
    (void)size;      // unused
    (void)alignment; // unused
    (void)offset;    // unused
    return NULL;     // not supported
}

#endif
