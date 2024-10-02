/*
 *
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <stdbool.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#include <umf/ipc.h>
#include <umf/memory_pool.h>
#include <umf/pools/pool_proxy.h>
#include <umf/pools/pool_scalable.h>
#include <umf/providers/provider_level_zero.h>
#include <umf/providers/provider_os_memory.h>

#ifdef UMF_BUILD_LIBUMF_POOL_DISJOINT
#include <umf/pools/pool_disjoint.h>
#endif

#ifdef UMF_BUILD_LIBUMF_POOL_JEMALLOC
#include <umf/pools/pool_jemalloc.h>
#endif

#include "utils_common.h"

#if (defined UMF_BUILD_LIBUMF_POOL_DISJOINT &&                                 \
     defined UMF_BUILD_LEVEL_ZERO_PROVIDER && defined UMF_BUILD_GPU_TESTS)
#include "utils_level_zero.h"
#endif

// NOTE: with strict compilation flags, ubench compilation throws some
// warnings. We disable them here because we do not want to change the ubench
// code.

// disable warning 6308:'realloc' might return null pointer: assigning null
// pointer to 'failed_benchmarks', which is passed as an argument to 'realloc',
// will cause the original memory block to be leaked.
// disable warning 6001: Using uninitialized memory
// '*ubench_state.benchmarks.name'.
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 6308)
#pragma warning(disable : 6001)
#endif // _MSC_VER

#include "ubench.h"
// BENCHMARK CONFIG
#define N_ITERATIONS 1000
#define ALLOC_SIZE (utils_get_page_size())

// OS MEMORY PROVIDER CONFIG
#define OS_MEMORY_PROVIDER_TRACE (0)

// DISJOINT POOL CONFIG
#define DISJOINT_POOL_SLAB_MIN_SIZE (ALLOC_SIZE)
#define DISJOINT_POOL_MAX_POOLABLE_SIZE (2 * ALLOC_SIZE)
#define DISJOINT_POOL_CAPACITY (N_ITERATIONS + 10)
#define DISJOINT_POOL_MIN_BUCKET_SIZE (ALLOC_SIZE)

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
    } while (array[i++].ptr != NULL && i < (int)iters);

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

////////////////// OS MEMORY PROVIDER

static umf_os_memory_provider_params_t UMF_OS_MEMORY_PROVIDER_PARAMS = {
    /* .protection = */ UMF_PROTECTION_READ | UMF_PROTECTION_WRITE,
    /* .visibility = */ UMF_MEM_MAP_PRIVATE,
    /* .shm_name = */ NULL,

    // NUMA config
    /* .numa_list = */ NULL,
    /* .numa_list_len = */ 0,

    /* .numa_mode = */ UMF_NUMA_MODE_DEFAULT,
    /* .part_size = */ 0,

    /* .partitions = */ NULL,
    /* .partitions_len = */ 0,
};

static void *w_umfMemoryProviderAlloc(void *provider, size_t size,
                                      size_t alignment) {
    void *ptr = NULL;
    umf_result_t umf_result;
    umf_memory_provider_handle_t hProvider =
        (umf_memory_provider_handle_t)provider;
    umf_result = umfMemoryProviderAlloc(hProvider, size, alignment, &ptr);
    if (umf_result != UMF_RESULT_SUCCESS || ptr == NULL) {
        fprintf(stderr, "error: umfMemoryProviderAlloc() failed\n");
        exit(-1);
    }

    return ptr;
}

static void w_umfMemoryProviderFree(void *provider, void *ptr, size_t size) {
    umf_result_t umf_result;
    umf_memory_provider_handle_t hProvider =
        (umf_memory_provider_handle_t)provider;
    umf_result = umfMemoryProviderFree(hProvider, ptr, size);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "error: umfMemoryProviderFree() failed\n");
        exit(-1);
    }
}

UBENCH_EX(simple, os_memory_provider) {
    alloc_t *array = alloc_array(N_ITERATIONS);

    umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = NULL;
    umf_result = umfMemoryProviderCreate(umfOsMemoryProviderOps(),
                                         &UMF_OS_MEMORY_PROVIDER_PARAMS,
                                         &os_memory_provider);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "error: umfMemoryProviderCreate() failed\n");
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
    umf_result_t umf_result;
    umf_memory_pool_handle_t hPool = (umf_memory_pool_handle_t)provider;
    umf_result = umfPoolFree(hPool, ptr);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "error: umfPoolFree() failed\n");
        exit(-1);
    }
}

////////////////// PROXY POOL WITH OS MEMORY PROVIDER

UBENCH_EX(simple, proxy_pool_with_os_memory_provider) {
    alloc_t *array = alloc_array(N_ITERATIONS);

    umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = NULL;
    umf_result = umfMemoryProviderCreate(umfOsMemoryProviderOps(),
                                         &UMF_OS_MEMORY_PROVIDER_PARAMS,
                                         &os_memory_provider);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "error: umfMemoryProviderCreate() failed\n");
        exit(-1);
    }

    umf_memory_pool_handle_t proxy_pool;
    umf_result = umfPoolCreate(umfProxyPoolOps(), os_memory_provider, NULL, 0,
                               &proxy_pool);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "error: umfPoolCreate() failed\n");
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

#if (defined UMF_BUILD_LIBUMF_POOL_DISJOINT)
////////////////// DISJOINT POOL WITH OS MEMORY PROVIDER

UBENCH_EX(simple, disjoint_pool_with_os_memory_provider) {
    alloc_t *array = alloc_array(N_ITERATIONS);

    umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = NULL;
    umf_result = umfMemoryProviderCreate(umfOsMemoryProviderOps(),
                                         &UMF_OS_MEMORY_PROVIDER_PARAMS,
                                         &os_memory_provider);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "error: umfMemoryProviderCreate() failed\n");
        exit(-1);
    }

    umf_disjoint_pool_params_t disjoint_memory_pool_params = {0};
    disjoint_memory_pool_params.SlabMinSize = DISJOINT_POOL_SLAB_MIN_SIZE;
    disjoint_memory_pool_params.MaxPoolableSize =
        DISJOINT_POOL_MAX_POOLABLE_SIZE;
    disjoint_memory_pool_params.Capacity = DISJOINT_POOL_CAPACITY;
    disjoint_memory_pool_params.MinBucketSize = DISJOINT_POOL_MIN_BUCKET_SIZE;

    umf_memory_pool_handle_t disjoint_pool;
    umf_result = umfPoolCreate(umfDisjointPoolOps(), os_memory_provider,
                               &disjoint_memory_pool_params, 0, &disjoint_pool);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "error: umfPoolCreate() failed\n");
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
#endif /* (defined UMF_BUILD_LIBUMF_POOL_DISJOINT) */

#if (defined UMF_BUILD_LIBUMF_POOL_JEMALLOC)
////////////////// JEMALLOC POOL WITH OS MEMORY PROVIDER

UBENCH_EX(simple, jemalloc_pool_with_os_memory_provider) {
    alloc_t *array = alloc_array(N_ITERATIONS);

    umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = NULL;
    umf_result = umfMemoryProviderCreate(umfOsMemoryProviderOps(),
                                         &UMF_OS_MEMORY_PROVIDER_PARAMS,
                                         &os_memory_provider);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "error: umfMemoryProviderCreate() failed\n");
        exit(-1);
    }

    umf_memory_pool_handle_t jemalloc_pool;
    umf_result = umfPoolCreate(umfJemallocPoolOps(), os_memory_provider, NULL,
                               0, &jemalloc_pool);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "error: umfPoolCreate() failed\n");
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
#endif /* (defined UMF_BUILD_LIBUMF_POOL_JEMALLOC) */

#if (defined UMF_POOL_SCALABLE_ENABLED)
////////////////// SCALABLE (TBB) POOL WITH OS MEMORY PROVIDER

UBENCH_EX(simple, scalable_pool_with_os_memory_provider) {
    alloc_t *array = alloc_array(N_ITERATIONS);

    umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = NULL;
    umf_result = umfMemoryProviderCreate(umfOsMemoryProviderOps(),
                                         &UMF_OS_MEMORY_PROVIDER_PARAMS,
                                         &os_memory_provider);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "error: umfMemoryProviderCreate() failed\n");
        exit(-1);
    }

    umf_memory_pool_handle_t scalable_pool;
    umf_result = umfPoolCreate(umfScalablePoolOps(), os_memory_provider, NULL,
                               0, &scalable_pool);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "error: umfPoolCreate() failed\n");
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
#endif /* (defined UMF_POOL_SCALABLE_ENABLED) */

#if (defined UMF_BUILD_LIBUMF_POOL_DISJOINT &&                                 \
     defined UMF_BUILD_LEVEL_ZERO_PROVIDER && defined UMF_BUILD_GPU_TESTS)
static void do_ipc_get_put_benchmark(alloc_t *allocs, size_t num_allocs,
                                     size_t repeats,
                                     umf_ipc_handle_t *ipc_handles) {
    for (size_t r = 0; r < repeats; ++r) {
        for (size_t i = 0; i < num_allocs; ++i) {
            size_t handle_size = 0;
            umf_result_t res =
                umfGetIPCHandle(allocs[i].ptr, &(ipc_handles[i]), &handle_size);
            if (res != UMF_RESULT_SUCCESS) {
                fprintf(stderr, "umfGetIPCHandle() failed\n");
            }
        }

        for (size_t i = 0; i < num_allocs; ++i) {
            umf_result_t res = umfPutIPCHandle(ipc_handles[i]);
            if (res != UMF_RESULT_SUCCESS) {
                fprintf(stderr, "umfPutIPCHandle() failed\n");
            }
        }
    }
}

int create_level_zero_params(level_zero_memory_provider_params_t *params) {
    uint32_t driver_idx = 0;
    ze_driver_handle_t driver = NULL;
    ze_context_handle_t context = NULL;
    ze_device_handle_t device = NULL;

    int ret = init_level_zero();
    if (ret != 0) {
        fprintf(stderr, "Failed to init Level 0!\n");
        return ret;
    }

    ret = find_driver_with_gpu(&driver_idx, &driver);
    if (ret || driver == NULL) {
        fprintf(stderr, "Cannot find L0 driver with GPU device!\n");
        return ret;
    }

    ret = create_context(driver, &context);
    if (ret != 0) {
        fprintf(stderr, "Failed to create L0 context!\n");
        return ret;
    }

    ret = find_gpu_device(driver, &device);
    if (ret || device == NULL) {
        fprintf(stderr, "Cannot find GPU device!\n");
        destroy_context(context);
        return ret;
    }

    params->level_zero_context_handle = context;
    params->level_zero_device_handle = device;
    params->memory_type = UMF_MEMORY_TYPE_DEVICE;

    return ret;
}

UBENCH_EX(ipc, disjoint_pool_with_level_zero_provider) {
    const size_t BUFFER_SIZE = 100;
    const size_t N_BUFFERS = 1000;
    level_zero_memory_provider_params_t level_zero_params = {0};

    int ret = create_level_zero_params(&level_zero_params);
    if (ret != 0) {
        exit(-1);
    }

    alloc_t *allocs = alloc_array(N_BUFFERS);
    if (allocs == NULL) {
        fprintf(stderr, "error: alloc_array() failed\n");
        goto err_destroy_context;
    }

    umf_ipc_handle_t *ipc_handles = calloc(N_BUFFERS, sizeof(umf_ipc_handle_t));
    if (ipc_handles == NULL) {
        fprintf(stderr, "error: calloc() failed\n");
        goto err_free_allocs;
    }

    umf_result_t umf_result;
    umf_memory_provider_handle_t provider = NULL;
    umf_result = umfMemoryProviderCreate(umfLevelZeroMemoryProviderOps(),
                                         &level_zero_params, &provider);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "error: umfMemoryProviderCreate() failed\n");
        goto err_free_ipc_handles;
    }

    umf_disjoint_pool_params_t disjoint_params = {0};
    disjoint_params.SlabMinSize = BUFFER_SIZE * 10;
    disjoint_params.MaxPoolableSize = 4ull * 1024ull * 1024ull;
    disjoint_params.Capacity = 64ull * 1024ull;
    disjoint_params.MinBucketSize = 64;
    umf_pool_create_flags_t flags = UMF_POOL_CREATE_FLAG_OWN_PROVIDER;
    umf_memory_pool_handle_t pool;
    umf_result = umfPoolCreate(umfDisjointPoolOps(), provider, &disjoint_params,
                               flags, &pool);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "error: umfPoolCreate() failed\n");
        umfMemoryProviderDestroy(provider);
        goto err_free_ipc_handles;
    }

    for (size_t i = 0; i < N_BUFFERS; ++i) {
        allocs[i].ptr = umfPoolMalloc(pool, BUFFER_SIZE);
        if (allocs[i].ptr == NULL) {
            goto err_buffer_destroy;
        }
        allocs[i].size = BUFFER_SIZE;
    }

    do_ipc_get_put_benchmark(allocs, N_BUFFERS, N_ITERATIONS,
                             ipc_handles); // WARMUP

    UBENCH_DO_BENCHMARK() {
        do_ipc_get_put_benchmark(allocs, N_BUFFERS, N_ITERATIONS, ipc_handles);
    }

err_buffer_destroy:
    for (size_t i = 0; i < N_BUFFERS; ++i) {
        umfPoolFree(pool, allocs[i].ptr);
    }

    umfPoolDestroy(pool);

err_free_ipc_handles:
    free(ipc_handles);

err_free_allocs:
    free(allocs);

err_destroy_context:
    destroy_context(level_zero_params.level_zero_context_handle);
}
#endif /* (defined UMF_BUILD_LIBUMF_POOL_DISJOINT && defined UMF_BUILD_LEVEL_ZERO_PROVIDER && defined UMF_BUILD_GPU_TESTS) */

// TODO add IPC benchmark for CUDA

UBENCH_MAIN()

#if defined(_MSC_VER)
#pragma warning(pop)
#endif // _MSC_VER
