/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include <umf/memory_pool.h>
#include <umf/pools/pool_disjoint.h>
#include <umf/providers/provider_cuda.h>

// disable warning 4201: nonstandard extension used: nameless struct/union
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4201)
#endif // _MSC_VER

#include <cuda.h>

#if defined(_MSC_VER)
#pragma warning(pop)
#endif // _MSC_VER

int main(void) {
    // A result object for storing UMF API result status
    umf_result_t res;

    CUdevice cuDevice;
    CUcontext cuContext;
    int ret = 0;

    // Initialize the CUDA driver API
    cuInit(0);

    // Get the handle to the first CUDA device
    cuDeviceGet(&cuDevice, 0);

    // Create a context on the device
    cuCtxCreate(&cuContext, 0, cuDevice);

    // Setup parameters for the CUDA Memory Provider. It will be used for
    // allocating memory from CUDA devices.
    umf_cuda_memory_provider_params_handle_t cu_memory_provider_params = NULL;
    res = umfCUDAMemoryProviderParamsCreate(&cu_memory_provider_params);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to create memory provider params!\n");
        ret = -1;
        goto cuda_destroy;
    }

    res = umfCUDAMemoryProviderParamsSetContext(cu_memory_provider_params,
                                                cuContext);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to set context in memory provider params!\n");
        ret = -1;
        goto provider_params_destroy;
    }

    res = umfCUDAMemoryProviderParamsSetDevice(cu_memory_provider_params,
                                               cuDevice);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to set device in memory provider params!\n");
        ret = -1;
        goto provider_params_destroy;
    }
    // Set the memory type to shared to allow the memory to be accessed on both
    // CPU and GPU.
    res = umfCUDAMemoryProviderParamsSetMemoryType(cu_memory_provider_params,
                                                   UMF_MEMORY_TYPE_SHARED);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "Failed to set memory type in memory provider params!\n");
        ret = -1;
        goto provider_params_destroy;
    }

    // Create CUDA memory provider
    umf_memory_provider_handle_t cu_memory_provider;
    res =
        umfMemoryProviderCreate(umfCUDAMemoryProviderOps(),
                                cu_memory_provider_params, &cu_memory_provider);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to create a memory provider!\n");
        ret = -1;
        goto provider_params_destroy;
    }

    printf("CUDA memory provider created at %p\n", (void *)cu_memory_provider);

    // Setup parameters for the Disjoint Pool. It will be used for managing the
    // memory allocated using memory provider.
    umf_disjoint_pool_params_handle_t hDisjointParams = NULL;
    res = umfDisjointPoolParamsCreate(&hDisjointParams);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "disjoint pool params create failed\n");
        ret = -1;
        goto memory_provider_destroy;
    }
    // Set the Slab Min Size to 64KB - the page size for GPU allocations
    res = umfDisjointPoolParamsSetSlabMinSize(hDisjointParams, 64 * 1024L);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to set the slab min size!\n");
        ret = -1;
        goto pool_params_destroy;
    }
    // We would keep only single slab per each allocation bucket
    res = umfDisjointPoolParamsSetCapacity(hDisjointParams, 1);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to set the capacity!\n");
        ret = -1;
        goto pool_params_destroy;
    }
    // Set the maximum poolable size to 64KB - objects with size above this
    // limit will not be stored/allocated from the pool.
    res = umfDisjointPoolParamsSetMaxPoolableSize(hDisjointParams, 64 * 1024L);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to set the max poolable size!\n");
        ret = -1;
        goto pool_params_destroy;
    }
    // Enable tracing
    res = umfDisjointPoolParamsSetTrace(hDisjointParams, 1);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to set the pool trace!\n");
        ret = -1;
        goto pool_params_destroy;
    }

    // Create Disjoint Pool memory pool.
    umf_memory_pool_handle_t cu_disjoint_memory_pool;
    res =
        umfPoolCreate(umfDisjointPoolOps(), cu_memory_provider, hDisjointParams,
                      UMF_POOL_CREATE_FLAG_NONE, &cu_disjoint_memory_pool);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to create a memory pool!\n");
        ret = -1;
        goto memory_provider_destroy;
    }

    printf("Disjoint Pool created at %p\n", (void *)cu_disjoint_memory_pool);

    // Allocate some memory from the pool
    int *ptr = umfPoolMalloc(cu_disjoint_memory_pool, sizeof(int));
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to allocate memory from the memory pool!\n");
        ret = -1;
        goto memory_pool_destroy;
    }

    // Use allocated memory
    *ptr = 1;

    // Free allocated memory
    res = umfFree(ptr);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to free memory to the pool!\n");
        ret = -1;
        goto memory_pool_destroy;
    }
    printf("Freed memory at %p\n", (void *)ptr);

    // Cleanup
memory_pool_destroy:
    umfPoolDestroy(cu_disjoint_memory_pool);

pool_params_destroy:
    umfDisjointPoolParamsDestroy(hDisjointParams);

memory_provider_destroy:
    umfMemoryProviderDestroy(cu_memory_provider);

provider_params_destroy:
    umfCUDAMemoryProviderParamsDestroy(cu_memory_provider_params);

cuda_destroy:
    ret = cuCtxDestroy(cuContext);
    return ret;
}
