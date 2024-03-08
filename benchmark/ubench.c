/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <umf/memory_pool.h>
#include <umf/pools/pool_proxy.h>
#include <umf/providers/provider_os_memory.h>

#ifdef UMF_BUILD_LIBUMF_POOL_DISJOINT
#include <umf/pools/pool_disjoint.h>
#endif

#ifdef UMF_BUILD_LIBUMF_POOL_JEMALLOC
#include <umf/pools/pool_jemalloc.h>
#endif

#ifdef UMF_BUILD_LIBUMF_POOL_SCALABLE
#include <umf/pools/pool_scalable.h>
#endif

#include <stdbool.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#include "ubench.h"
#include "utils_common.h"

// BENCHMARK CONFIG
#define N_ITERATIONS 1000
#define ALLOC_SIZE (util_get_page_size())

// OS MEMORY PROVIDER CONFIG
#define OS_MEMORY_PROVIDER_TRACE (0)

// DISJOINT POOL CONFIG
#define DISJOINT_POOL_SLAB_MIN_SIZE (ALLOC_SIZE)
#define DISJOINT_POOL_MAX_POOLABLE_SIZE (2 * ALLOC_SIZE)
#define DISJOINT_POOL_CAPACITY (N_ITERATIONS + 10)
#define DISJOINT_POOL_MIN_BUCKET_SIZE (ALLOC_SIZE)
#define DISJOINT_POOL_TRACE (0)

typedef struct alloc_s {
    void *ptr;
    size_t size;
} alloc_t;

typedef void *(*malloc_t)(void *provider, size_t size, size_t alignment);
typedef void (*free_t)(void *provider, void *ptr, size_t size);

static int Alloc_size;

static void do_benchmark(alloc_t *array, size_t iters, malloc_t malloc_f,
                         free_t free_f, void *provider) {
    int i = 0;
    do {
        array[i].ptr = malloc_f(provider, Alloc_size, 0);
    } while (array[i++].ptr != NULL && i < iters);

    while (--i >= 0) {
        free_f(provider, array[i].ptr, Alloc_size);
    }
}

static alloc_t *alloc_array(size_t iters) {
    Alloc_size = (int)ALLOC_SIZE;
    alloc_t *array = malloc(iters * sizeof(alloc_t));
    if (array == NULL) {
        perror("malloc() failed");
        exit(-1);
    }
    return array;
}

////////////////// GLIBC

static void *glibc_malloc(void *provider, size_t size, size_t alignment) {
    (void)provider;  // unused
    (void)alignment; // unused
    return malloc(size);
}

static void glibc_free(void *provider, void *ptr, size_t size) {
    (void)provider; // unused
    (void)size;     // unused
    free(ptr);
}

UBENCH_EX(simple, glibc_malloc) {
    alloc_t *array = alloc_array(N_ITERATIONS);

    do_benchmark(array, N_ITERATIONS, glibc_malloc, glibc_free, NULL); // WARMUP

    UBENCH_DO_BENCHMARK() {
        do_benchmark(array, N_ITERATIONS, glibc_malloc, glibc_free, NULL);
    }

    free(array);
}

#ifdef UMF_BUILD_OS_MEMORY_PROVIDER
////////////////// OS MEMORY PROVIDER

static umf_os_memory_provider_params_t UMF_OS_MEMORY_PROVIDER_PARAMS = {
    /* .protection = */ UMF_PROTECTION_READ | UMF_PROTECTION_WRITE,

    // NUMA config
    /* .nodemask = */ NULL,
    /* .maxnode = */ 0,
    /* .numa_mode = */ UMF_NUMA_MODE_DEFAULT,

    // others
    /* .traces = */ OS_MEMORY_PROVIDER_TRACE,
};

static void *w_umfMemoryProviderAlloc(void *provider, size_t size,
                                      size_t alignment) {
    void *ptr = NULL;
    enum umf_result_t umf_result;
    umf_memory_provider_handle_t hProvider =
        (umf_memory_provider_handle_t)provider;
    umf_result = umfMemoryProviderAlloc(hProvider, size, alignment, &ptr);
    if (umf_result != UMF_RESULT_SUCCESS || ptr == NULL) {
        exit(-1);
    }

    return ptr;
}

static void w_umfMemoryProviderFree(void *provider, void *ptr, size_t size) {
    enum umf_result_t umf_result;
    umf_memory_provider_handle_t hProvider =
        (umf_memory_provider_handle_t)provider;
    umf_result = umfMemoryProviderFree(hProvider, ptr, size);
    if (umf_result != UMF_RESULT_SUCCESS) {
        exit(-1);
    }
}

UBENCH_EX(simple, os_memory_provider) {
    alloc_t *array = alloc_array(N_ITERATIONS);

    enum umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = NULL;
    umf_result = umfMemoryProviderCreate(umfOsMemoryProviderOps(),
                                         &UMF_OS_MEMORY_PROVIDER_PARAMS,
                                         &os_memory_provider);
    if (umf_result != UMF_RESULT_SUCCESS) {
        exit(-1);
    }

    do_benchmark(array, N_ITERATIONS, w_umfMemoryProviderAlloc,
                 w_umfMemoryProviderFree, os_memory_provider); // WARMUP

    UBENCH_DO_BENCHMARK() {
        do_benchmark(array, N_ITERATIONS, w_umfMemoryProviderAlloc,
                     w_umfMemoryProviderFree, os_memory_provider);
    }

    umfMemoryProviderDestroy(os_memory_provider);
    free(array);
}

static void *w_umfPoolMalloc(void *provider, size_t size, size_t alignment) {
    (void)alignment; // unused
    umf_memory_pool_handle_t hPool = (umf_memory_pool_handle_t)provider;
    return umfPoolMalloc(hPool, size);
}

static void w_umfPoolFree(void *provider, void *ptr, size_t size) {
    (void)size; // unused
    enum umf_result_t umf_result;
    umf_memory_pool_handle_t hPool = (umf_memory_pool_handle_t)provider;
    umf_result = umfPoolFree(hPool, ptr);
    if (umf_result != UMF_RESULT_SUCCESS) {
        exit(-1);
    }
}

////////////////// PROXY POOL WITH OS MEMORY PROVIDER

UBENCH_EX(simple, proxy_pool_with_os_memory_provider) {
    alloc_t *array = alloc_array(N_ITERATIONS);

    enum umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = NULL;
    umf_result = umfMemoryProviderCreate(umfOsMemoryProviderOps(),
                                         &UMF_OS_MEMORY_PROVIDER_PARAMS,
                                         &os_memory_provider);
    if (umf_result != UMF_RESULT_SUCCESS) {
        exit(-1);
    }

    umf_memory_pool_handle_t proxy_pool;
    umf_result = umfPoolCreate(umfProxyPoolOps(), os_memory_provider, NULL, 0,
                               &proxy_pool);
    if (umf_result != UMF_RESULT_SUCCESS) {
        exit(-1);
    }

    do_benchmark(array, N_ITERATIONS, w_umfPoolMalloc, w_umfPoolFree,
                 proxy_pool); // WARMUP

    UBENCH_DO_BENCHMARK() {
        do_benchmark(array, N_ITERATIONS, w_umfPoolMalloc, w_umfPoolFree,
                     proxy_pool);
    }

    umfPoolDestroy(proxy_pool);
    umfMemoryProviderDestroy(os_memory_provider);
    free(array);
}

#endif /* UMF_BUILD_OS_MEMORY_PROVIDER */

#if (defined UMF_BUILD_LIBUMF_POOL_DISJOINT) &&                                \
    (defined UMF_BUILD_OS_MEMORY_PROVIDER)
////////////////// DISJOINT POOL WITH OS MEMORY PROVIDER

UBENCH_EX(simple, disjoint_pool_with_os_memory_provider) {
    alloc_t *array = alloc_array(N_ITERATIONS);

    enum umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = NULL;
    umf_result = umfMemoryProviderCreate(umfOsMemoryProviderOps(),
                                         &UMF_OS_MEMORY_PROVIDER_PARAMS,
                                         &os_memory_provider);
    if (umf_result != UMF_RESULT_SUCCESS) {
        exit(-1);
    }

    umf_disjoint_pool_params_t disjoint_memory_pool_params = {0};
    disjoint_memory_pool_params.SlabMinSize = DISJOINT_POOL_SLAB_MIN_SIZE;
    disjoint_memory_pool_params.MaxPoolableSize =
        DISJOINT_POOL_MAX_POOLABLE_SIZE;
    disjoint_memory_pool_params.Capacity = DISJOINT_POOL_CAPACITY;
    disjoint_memory_pool_params.MinBucketSize = DISJOINT_POOL_MIN_BUCKET_SIZE;
    disjoint_memory_pool_params.PoolTrace = DISJOINT_POOL_TRACE;

    umf_memory_pool_handle_t disjoint_pool;
    umf_result = umfPoolCreate(umfDisjointPoolOps(), os_memory_provider,
                               &disjoint_memory_pool_params, 0, &disjoint_pool);
    if (umf_result != UMF_RESULT_SUCCESS) {
        exit(-1);
    }

    do_benchmark(array, N_ITERATIONS, w_umfPoolMalloc, w_umfPoolFree,
                 disjoint_pool); // WARMUP

    UBENCH_DO_BENCHMARK() {
        do_benchmark(array, N_ITERATIONS, w_umfPoolMalloc, w_umfPoolFree,
                     disjoint_pool);
    }

    umfPoolDestroy(disjoint_pool);
    umfMemoryProviderDestroy(os_memory_provider);
    free(array);
}
#endif /* (defined UMF_BUILD_LIBUMF_POOL_DISJOINT) && (defined UMF_BUILD_OS_MEMORY_PROVIDER) */

#if (defined UMF_BUILD_LIBUMF_POOL_JEMALLOC) &&                                \
    (defined UMF_BUILD_OS_MEMORY_PROVIDER)
////////////////// JEMALLOC POOL WITH OS MEMORY PROVIDER

UBENCH_EX(simple, jemalloc_pool_with_os_memory_provider) {
    alloc_t *array = alloc_array(N_ITERATIONS);

    enum umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = NULL;
    umf_result = umfMemoryProviderCreate(umfOsMemoryProviderOps(),
                                         &UMF_OS_MEMORY_PROVIDER_PARAMS,
                                         &os_memory_provider);
    if (umf_result != UMF_RESULT_SUCCESS) {
        exit(-1);
    }

    umf_memory_pool_handle_t jemalloc_pool;
    umf_result = umfPoolCreate(umfJemallocPoolOps(), os_memory_provider, NULL,
                               0, &jemalloc_pool);
    if (umf_result != UMF_RESULT_SUCCESS) {
        exit(-1);
    }

    do_benchmark(array, N_ITERATIONS, w_umfPoolMalloc, w_umfPoolFree,
                 jemalloc_pool); // WARMUP

    UBENCH_DO_BENCHMARK() {
        do_benchmark(array, N_ITERATIONS, w_umfPoolMalloc, w_umfPoolFree,
                     jemalloc_pool);
    }

    umfPoolDestroy(jemalloc_pool);
    umfMemoryProviderDestroy(os_memory_provider);
    free(array);
}
#endif /* (defined UMF_BUILD_LIBUMF_POOL_JEMALLOC) && (defined UMF_BUILD_OS_MEMORY_PROVIDER) */

#if (defined UMF_BUILD_LIBUMF_POOL_SCALABLE) &&                                \
    (defined UMF_BUILD_OS_MEMORY_PROVIDER)
////////////////// SCALABLE (TBB) POOL WITH OS MEMORY PROVIDER

UBENCH_EX(simple, scalable_pool_with_os_memory_provider) {
    alloc_t *array = alloc_array(N_ITERATIONS);

    enum umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = NULL;
    umf_result = umfMemoryProviderCreate(umfOsMemoryProviderOps(),
                                         &UMF_OS_MEMORY_PROVIDER_PARAMS,
                                         &os_memory_provider);
    if (umf_result != UMF_RESULT_SUCCESS) {
        exit(-1);
    }

    umf_memory_pool_handle_t scalable_pool;
    umf_result = umfPoolCreate(umfScalablePoolOps(), os_memory_provider, NULL,
                               0, &scalable_pool);
    if (umf_result != UMF_RESULT_SUCCESS) {
        exit(-1);
    }

    do_benchmark(array, N_ITERATIONS, w_umfPoolMalloc, w_umfPoolFree,
                 scalable_pool); // WARMUP

    UBENCH_DO_BENCHMARK() {
        do_benchmark(array, N_ITERATIONS, w_umfPoolMalloc, w_umfPoolFree,
                     scalable_pool);
    }

    umfPoolDestroy(scalable_pool);
    umfMemoryProviderDestroy(os_memory_provider);
    free(array);
}
#endif /* (defined UMF_BUILD_LIBUMF_POOL_SCALABLE) && (defined UMF_BUILD_OS_MEMORY_PROVIDER) */

UBENCH_MAIN()
