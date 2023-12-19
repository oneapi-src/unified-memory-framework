/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <umf/pools/pool_disjoint.h>
#include <umf/providers/provider_coarse.h>
#include <umf/providers/provider_os_memory.h>

#include <stdbool.h>
#include <unistd.h>

#include "ubench.h"

// BENCHMARK CONFIG
#define N_ITERATIONS 1000
#define ALLOC_SIZE (getpagesize())

// OS MEMORY PROVIDER CONFIG
#define OS_MEMORY_PROVIDER_TRACE (0)

// COARSE MEMORY PROVIDER CONFIG
#define COARSE_MEMORY_PROVIDER_INIT_BUFFER_SIZE (2 * N_ITERATIONS * ALLOC_SIZE)
#define COARSE_MEMORY_PROVIDER_TRACE (0)

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
    Alloc_size = ALLOC_SIZE;
    alloc_t *array = malloc(iters * sizeof(alloc_t));
    if (array == NULL) {
        perror("malloc() failed");
        exit(-1);
    }
    return array;
}

////////////////// GLIBC

static void *glibc_malloc(void *provider, size_t size, size_t alignment) {
    return malloc(size);
}

static void glibc_free(void *provider, void *ptr, size_t size) { free(ptr); }

UBENCH_EX(simple, glibc_malloc) {
    alloc_t *array = alloc_array(N_ITERATIONS);

    do_benchmark(array, N_ITERATIONS, glibc_malloc, glibc_free, NULL); // WARMUP

    UBENCH_DO_BENCHMARK() {
        do_benchmark(array, N_ITERATIONS, glibc_malloc, glibc_free, NULL);
    }

    free(array);
}

////////////////// OS MEMORY PROVIDER

static umf_os_memory_provider_params_t UMF_OS_MEMORY_PROVIDER_PARAMS = {
    /* .protection = */ UMF_PROTECTION_READ | UMF_PROTECTION_WRITE,
    /* .visibility = */ UMF_VISIBILITY_PRIVATE,

    // NUMA config
    /* .nodemask = */ NULL,
    /* .maxnode = */ 0,
    /* .numa_mode = */ UMF_NUMA_MODE_DEFAULT,
    /* .numa_flags = */ 0,

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
    umf_result = umfMemoryProviderCreate(&UMF_OS_MEMORY_PROVIDER_OPS,
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

////////////////// COARSE WITH OS MEMORY PROVIDER

UBENCH_EX(simple, coarse_with_os_memory_provider) {
    alloc_t *array = alloc_array(N_ITERATIONS);

    enum umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = NULL;
    umf_result = umfMemoryProviderCreate(&UMF_OS_MEMORY_PROVIDER_OPS,
                                         &UMF_OS_MEMORY_PROVIDER_PARAMS,
                                         &os_memory_provider);
    if (umf_result != UMF_RESULT_SUCCESS) {
        exit(-1);
    }

    coarse_memory_provider_params_t coarse_memory_provider_params = {
        os_memory_provider, // upstream_memory_provider
        COARSE_MEMORY_PROVIDER_INIT_BUFFER_SIZE,
        true,                         // immediate_init
        COARSE_MEMORY_PROVIDER_TRACE, // trace
    };

    umf_memory_provider_handle_t coarse_memory_provider;
    umfMemoryProviderCreate(&UMF_COARSE_MEMORY_PROVIDER_OPS,
                            &coarse_memory_provider_params,
                            &coarse_memory_provider);
    if (umf_result != UMF_RESULT_SUCCESS) {
        exit(-1);
    }

    do_benchmark(array, N_ITERATIONS, w_umfMemoryProviderAlloc,
                 w_umfMemoryProviderFree, coarse_memory_provider); // WARMUP

    UBENCH_DO_BENCHMARK() {
        do_benchmark(array, N_ITERATIONS, w_umfMemoryProviderAlloc,
                     w_umfMemoryProviderFree, coarse_memory_provider);
    }

    umfMemoryProviderDestroy(coarse_memory_provider);
    umfMemoryProviderDestroy(os_memory_provider);
    free(array);
}

////////////////// DISJOINT POOL WITH OS MEMORY PROVIDER

static void *w_umfPoolMalloc(void *provider, size_t size, size_t alignment) {
    umf_memory_pool_handle_t hPool = (umf_memory_pool_handle_t)provider;
    return umfPoolMalloc(hPool, size);
}

static void w_umfPoolFree(void *provider, void *ptr, size_t size) {
    enum umf_result_t umf_result;
    umf_memory_pool_handle_t hPool = (umf_memory_pool_handle_t)provider;
    umf_result = umfPoolFree(hPool, ptr);
    if (umf_result != UMF_RESULT_SUCCESS) {
        exit(-1);
    }
}

UBENCH_EX(simple, disjoint_pool_with_os_memory_provider) {
    alloc_t *array = alloc_array(N_ITERATIONS);

    enum umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = NULL;
    umf_result = umfMemoryProviderCreate(&UMF_OS_MEMORY_PROVIDER_OPS,
                                         &UMF_OS_MEMORY_PROVIDER_PARAMS,
                                         &os_memory_provider);
    if (umf_result != UMF_RESULT_SUCCESS) {
        exit(-1);
    }

    umf_disjoint_pool_params_t disjoint_memory_pool_params = {};
    disjoint_memory_pool_params.SlabMinSize = DISJOINT_POOL_SLAB_MIN_SIZE;
    disjoint_memory_pool_params.MaxPoolableSize =
        DISJOINT_POOL_MAX_POOLABLE_SIZE;
    disjoint_memory_pool_params.Capacity = DISJOINT_POOL_CAPACITY;
    disjoint_memory_pool_params.MinBucketSize = DISJOINT_POOL_MIN_BUCKET_SIZE;
    disjoint_memory_pool_params.PoolTrace = DISJOINT_POOL_TRACE;

    umf_memory_pool_handle_t disjoint_pool;
    umf_result = umfPoolCreate(&UMF_DISJOINT_POOL_OPS, os_memory_provider,
                               &disjoint_memory_pool_params, &disjoint_pool);
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

UBENCH_MAIN();
