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
 * - malloc_usable_size()
 * - realloc()
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <umf/memory_pool.h>
#include <umf/memory_provider.h>
#include <umf/providers/provider_os_memory.h>

#include "base_alloc_global.h"
#include "proxy_lib.h"
#include "utils_common.h"
#include "utils_concurrency.h"

/*
 * The UMF proxy library uses two memory allocators:
 * 1) base_alloc for bootstrapping
 * 2) the main one - UMF pool allocator.
 *
 * Ad 1)
 * The base allocator is used from the very beginning
 * to the creation of a UMF pool in the constructor of the proxy library.
 * It is used to allocate memory for OS specific data used during loading and unloading
 * applications (for example _dl_init() and _dl_fini() on Linux storing data of all
 * constructors and destructors that have to be called) and also memory needed
 * by umfMemoryProviderCreate() and umfPoolCreate().
 *
 * Ad 2)
 * The UMF pool allocator (the main one) is used from the creation to the destruction
 * of a UMF pool to allocate memory needed by an application. It should be freed
 * by an application.
 */

static umf_memory_provider_handle_t OS_memory_provider = NULL;
static umf_memory_pool_handle_t Proxy_pool = NULL;

// it protects us from recursion in umfPool*()
static __TLS int was_called_from_umfPool = 0;

/*****************************************************************************/
/*** The constructor and destructor of the proxy library *********************/
/*****************************************************************************/

void proxy_lib_create_common(void) {
    umf_os_memory_provider_params_t os_params =
        umfOsMemoryProviderParamsDefault();
    enum umf_result_t umf_result;

    umf_result = umfMemoryProviderCreate(umfOsMemoryProviderOps(), &os_params,
                                         &OS_memory_provider);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "error: creating OS memory provider failed\n");
        exit(-1);
    }

    umf_result = umfPoolCreate(umfPoolManagerOps(), OS_memory_provider, NULL, 0,
                               &Proxy_pool);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "error: creating UMF pool manager failed\n");
        exit(-1);
    }
    // The UMF pool has just been created (Proxy_pool != NULL). Stop using
    // the base allocator and start using the UMF pool allocator from now on.
}

void proxy_lib_destroy_common(void) {
    umfPoolDestroy(Proxy_pool);
    Proxy_pool = NULL;

    umfMemoryProviderDestroy(OS_memory_provider);
    OS_memory_provider = NULL;

    umf_ba_destroy_global();
}

/*****************************************************************************/
/*** Generic version of realloc() of base allocator *******************/
/*****************************************************************************/

static inline void *ba_alloc_global_realloc(void *ptr, size_t new_size) {
    assert(ptr);      // it should be verified in the main realloc()
    assert(new_size); // it should be verified in the main realloc()

    void *new_ptr = umf_ba_global_alloc(new_size);
    if (!new_ptr) {
        return NULL;
    }

    size_t old_size = umf_ba_global_malloc_usable_size(ptr);

    if (new_size > old_size) {
        new_size = old_size;
    }

    memcpy(new_ptr, ptr, new_size);

    // we can free the old ptr now
    umf_ba_global_free(ptr);

    return new_ptr;
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

    return umf_ba_global_alloc(size);
}

void *calloc(size_t nmemb, size_t size) {
    if (!was_called_from_umfPool && Proxy_pool) {
        was_called_from_umfPool = 1;
        void *ptr = umfPoolCalloc(Proxy_pool, nmemb, size);
        was_called_from_umfPool = 0;
        return ptr;
    }

    void *ptr = umf_ba_global_alloc(nmemb * size);
    if (ptr) {
        memset(ptr, 0, nmemb * size);
    }
    return ptr;
}

void *realloc(void *ptr, size_t size) {
    if (ptr == NULL) {
        return malloc(size);
    }

    if (size == 0) {
        free(ptr);
        return NULL;
    }

    if (!was_called_from_umfPool && Proxy_pool) {
        was_called_from_umfPool = 1;
        void *new_ptr = umfPoolRealloc(Proxy_pool, ptr, size);
        was_called_from_umfPool = 0;
        return new_ptr;
    }

    return ba_alloc_global_realloc(ptr, size);
}

void free(void *ptr) {
    if (ptr == NULL) {
        return;
    }

    if (!was_called_from_umfPool && Proxy_pool) {
        was_called_from_umfPool = 1;
        if (umfPoolFree(Proxy_pool, ptr) != UMF_RESULT_SUCCESS) {
            fprintf(stderr, "error: umfPoolFree() failed\n");
            assert(0);
        }
        was_called_from_umfPool = 0;
        return;
    }

    umf_ba_global_free(ptr);
}

void *aligned_alloc(size_t alignment, size_t size) {
    if (!was_called_from_umfPool && Proxy_pool) {
        was_called_from_umfPool = 1;
        void *ptr = umfPoolAlignedMalloc(Proxy_pool, size, alignment);
        was_called_from_umfPool = 0;
        return ptr;
    }

    return umf_ba_global_aligned_alloc(size, alignment);
}

size_t malloc_usable_size(void *ptr) {
    if (!was_called_from_umfPool && Proxy_pool) {
        was_called_from_umfPool = 1;
        size_t size = umfPoolMallocUsableSize(Proxy_pool, ptr);
        was_called_from_umfPool = 0;
        return size;
    }

    return umf_ba_global_malloc_usable_size(ptr);
}
