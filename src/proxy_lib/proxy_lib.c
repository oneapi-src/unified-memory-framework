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

#ifndef _WIN32
#define _GNU_SOURCE // for RTLD_NEXT
#include <dlfcn.h>
#undef _GNU_SOURCE
#endif /* _WIN32 */

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
#include "utils_load_library.h"
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
#ifndef _WIN32
typedef void *(*system_aligned_alloc_t)(size_t alignment, size_t size);
typedef void *(*system_calloc_t)(size_t nmemb, size_t size);
typedef void (*system_free_t)(void *ptr);
typedef void *(*system_malloc_t)(size_t size);
typedef size_t (*system_malloc_usable_size_t)(void *ptr);
typedef void *(*system_realloc_t)(void *ptr, size_t size);

// pointers to the default system allocator's API
static system_aligned_alloc_t System_aligned_alloc;
static system_calloc_t System_calloc;
static system_free_t System_free;
static system_malloc_t System_malloc;
static system_malloc_usable_size_t System_malloc_usable_size;
static system_realloc_t System_realloc;

static size_t Size_threshold_value = 0;
#endif /* _WIN32 */

static UTIL_ONCE_FLAG Base_alloc_leak_initialized = UTIL_ONCE_FLAG_INIT;
static umf_ba_linear_pool_t *Base_alloc_leak = NULL;
static umf_memory_provider_handle_t OS_memory_provider = NULL;
static umf_memory_pool_handle_t Proxy_pool = NULL;

// it protects us from recursion in umfPool*()
static __TLS int was_called_from_umfPool = 0;

// This WA for the issue:
// https://github.com/oneapi-src/unified-memory-framework/issues/894
// It protects us from a recursion in malloc_usable_size()
// when the JEMALLOC proxy_lib_pool is used.
// TODO remove this WA when the issue is fixed.
static __TLS int was_called_from_malloc_usable_size = 0;

/*****************************************************************************/
/*** The constructor and destructor of the proxy library *********************/
/*****************************************************************************/

#ifndef _WIN32
static size_t get_size_threshold(void) {
    char *str_threshold = utils_env_var_get_str("UMF_PROXY", "size.threshold=");
    LOG_DEBUG("UMF_PROXY[size.threshold] = %s", str_threshold);
    long threshold = utils_get_size_threshold(str_threshold);
    if (threshold < 0) {
        LOG_ERR("incorrect size threshold: %s", str_threshold);
        exit(-1);
    }

    return (size_t)threshold;
}

static int get_system_allocator_symbols(void) {
    *((void **)(&System_aligned_alloc)) =
        utils_get_symbol_addr(RTLD_NEXT, "aligned_alloc", NULL);
    *((void **)(&System_calloc)) =
        utils_get_symbol_addr(RTLD_NEXT, "calloc", NULL);
    *((void **)(&System_free)) = utils_get_symbol_addr(RTLD_NEXT, "free", NULL);
    *((void **)(&System_malloc)) =
        utils_get_symbol_addr(RTLD_NEXT, "malloc", NULL);
    *((void **)(&System_malloc_usable_size)) =
        utils_get_symbol_addr(RTLD_NEXT, "malloc_usable_size", NULL);
    *((void **)(&System_realloc)) =
        utils_get_symbol_addr(RTLD_NEXT, "realloc", NULL);

    if (System_aligned_alloc && System_calloc && System_free && System_malloc &&
        System_malloc_usable_size && System_realloc) {
        return 0;
    }

    return -1;
}
#endif /* _WIN32 */

void proxy_lib_create_common(void) {
    utils_log_init();
    umf_os_memory_provider_params_handle_t os_params = NULL;
    umf_result_t umf_result;

    umf_result = umfOsMemoryProviderParamsCreate(&os_params);
    if (umf_result != UMF_RESULT_SUCCESS) {
        LOG_ERR("creating OS memory provider params failed");
        exit(-1);
    }

#ifndef _WIN32
    size_t _threshold = get_size_threshold();
    if (_threshold > 0) {
        if (get_system_allocator_symbols()) {
            LOG_ERR("initialization of the system allocator failed!");
            exit(-1);
        }

        Size_threshold_value = _threshold;
        LOG_INFO("system allocator initialized, size threshold value = %zu",
                 Size_threshold_value);
    }

    if (utils_env_var_has_str("UMF_PROXY", "page.disposition=shared-fd")) {
        LOG_INFO("proxy_lib: using the MAP_SHARED visibility mode with the "
                 "file descriptor duplication");
        umf_result = umfOsMemoryProviderParamsSetVisibility(os_params,
                                                            UMF_MEM_MAP_SHARED);
        if (umf_result != UMF_RESULT_SUCCESS) {
            LOG_ERR("setting visibility mode failed");
            exit(-1);
        }
        umf_result = umfOsMemoryProviderParamsSetShmName(os_params, NULL);
        if (umf_result != UMF_RESULT_SUCCESS) {
            LOG_ERR("setting shared memory name failed");
            exit(-1);
        }
    } else if (utils_env_var_has_str("UMF_PROXY",
                                     "page.disposition=shared-shm")) {
        umf_result = umfOsMemoryProviderParamsSetVisibility(os_params,
                                                            UMF_MEM_MAP_SHARED);
        if (umf_result != UMF_RESULT_SUCCESS) {
            LOG_ERR("setting visibility mode failed");
            exit(-1);
        }

        char shm_name[NAME_MAX];
        memset(shm_name, 0, NAME_MAX);
        sprintf(shm_name, "umf_proxy_lib_shm_pid_%i", utils_getpid());
        umf_result = umfOsMemoryProviderParamsSetShmName(os_params, shm_name);
        if (umf_result != UMF_RESULT_SUCCESS) {
            LOG_ERR("setting shared memory name failed");
            exit(-1);
        }

        LOG_INFO("proxy_lib: using the MAP_SHARED visibility mode with the "
                 "named shared memory: %s",
                 shm_name);
    }
#endif /* _WIN32 */

    umf_result = umfMemoryProviderCreate(umfOsMemoryProviderOps(), os_params,
                                         &OS_memory_provider);
    umfOsMemoryProviderParamsDestroy(os_params);
    if (umf_result != UMF_RESULT_SUCCESS) {
        LOG_ERR("creating OS memory provider failed");
        exit(-1);
    }

    umf_result = umfPoolCreate(umfPoolManagerOps(), OS_memory_provider, NULL, 0,
                               &Proxy_pool);
    if (umf_result != UMF_RESULT_SUCCESS) {
        LOG_ERR("creating UMF pool manager failed");
        exit(-1);
    }

    // The UMF pool has just been created (Proxy_pool != NULL). Stop using
    // the linear allocator and start using the UMF pool allocator from now on.
    LOG_DEBUG("proxy library initialized");
}

void proxy_lib_destroy_common(void) {
    if (utils_is_running_in_proxy_lib()) {
        // We cannot destroy 'Base_alloc_leak' nor 'Proxy_pool' nor 'OS_memory_provider',
        // because it could lead to use-after-free in the program's unloader
        // (for example _dl_fini() on Linux).
        goto fini_proxy_lib_destroy_common;
    }

    umf_memory_pool_handle_t pool = Proxy_pool;
    Proxy_pool = NULL;
    umfPoolDestroy(pool);

    umf_memory_provider_handle_t provider = OS_memory_provider;
    OS_memory_provider = NULL;
    umfMemoryProviderDestroy(provider);
    LOG_DEBUG("proxy library destroyed");

fini_proxy_lib_destroy_common:
    LOG_DEBUG("proxy library finalized");
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

static inline void *ba_leak_aligned_alloc(size_t alignment, size_t size) {
    ba_leak_init_once();
    void *ptr = umf_ba_linear_alloc(Base_alloc_leak, size + alignment);
    return (void *)ALIGN_UP_SAFE((uintptr_t)ptr, alignment);
}

static inline void *ba_leak_malloc(size_t size) {
    return ba_leak_aligned_alloc(0, size);
}

static inline void *ba_leak_calloc(size_t nmemb, size_t size) {
    ba_leak_init_once();
    // umf_ba_linear_alloc() returns zeroed memory
    // so ba_leak_aligned_alloc() does too
    return ba_leak_aligned_alloc(0, nmemb * size);
}

static inline void *ba_leak_realloc(void *ptr, size_t size, size_t max_size) {
    ba_leak_init_once();
    return ba_generic_realloc(Base_alloc_leak, ptr, size, max_size);
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
#ifndef _WIN32
    if (size < Size_threshold_value) {
        return System_malloc(size);
    }
#endif /* _WIN32 */

    if (!was_called_from_umfPool && Proxy_pool) {
        was_called_from_umfPool = 1;
        void *ptr = umfPoolMalloc(Proxy_pool, size);
        was_called_from_umfPool = 0;
        return ptr;
    }

    return ba_leak_malloc(size);
}

void *calloc(size_t nmemb, size_t size) {
#ifndef _WIN32
    if ((nmemb * size) < Size_threshold_value) {
        return System_calloc(nmemb, size);
    }
#endif /* _WIN32 */

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

    if (Proxy_pool && (umfPoolByPtr(ptr) == Proxy_pool)) {
        if (umfPoolFree(Proxy_pool, ptr) != UMF_RESULT_SUCCESS) {
            LOG_ERR("umfPoolFree() failed");
        }
        return;
    }

#ifndef _WIN32
    if (Size_threshold_value) {
        System_free(ptr);
        return;
    }
#endif /* _WIN32 */

    LOG_ERR("free() failed: %p", ptr);

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

    if (Proxy_pool && (umfPoolByPtr(ptr) == Proxy_pool)) {
        was_called_from_umfPool = 1;
        void *new_ptr = umfPoolRealloc(Proxy_pool, ptr, size);
        was_called_from_umfPool = 0;
        return new_ptr;
    }

#ifndef _WIN32
    if (Size_threshold_value) {
        return System_realloc(ptr, size);
    }
#endif /* _WIN32 */

    LOG_ERR("realloc() failed: %p", ptr);

    return NULL;
}

void *aligned_alloc(size_t alignment, size_t size) {
#ifndef _WIN32
    if (size < Size_threshold_value) {
        return System_aligned_alloc(alignment, size);
    }
#endif /* _WIN32 */

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
    // a check to verify if we are running the proxy library
    if (ptr == (void *)0x01) {
        return 0xDEADBEEF;
    }

    if (ba_leak_pool_contains_pointer(ptr)) {
        return 0; // unsupported in case of the ba_leak allocator
    }

    if (!was_called_from_malloc_usable_size && Proxy_pool &&
        (umfPoolByPtr(ptr) == Proxy_pool)) {
        was_called_from_malloc_usable_size = 1;
        was_called_from_umfPool = 1;
        size_t size = umfPoolMallocUsableSize(Proxy_pool, ptr);
        was_called_from_umfPool = 0;
        was_called_from_malloc_usable_size = 0;
        return size;
    }

#ifndef _WIN32
    if (!was_called_from_malloc_usable_size && Size_threshold_value) {
        return System_malloc_usable_size(ptr);
    }
#endif /* _WIN32 */

    LOG_ERR("malloc_usable_size() failed: %p", ptr);

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
