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

#include <cuda.h>

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

    // Setup parameters for the CUDA memory provider. It will be used for
    // allocating memory from CUDA devices.
    cuda_memory_provider_params_t cu_memory_provider_params;
    cu_memory_provider_params.cuda_context_handle = cuContext;
    cu_memory_provider_params.cuda_device_handle = cuDevice;
    // Set the memory type to shared to allow the memory to be accessed on both
    // CPU and GPU.
    cu_memory_provider_params.memory_type = UMF_MEMORY_TYPE_SHARED;

    // Create CUDA memory provider
    umf_memory_provider_handle_t cu_memory_provider;
    res = umfMemoryProviderCreate(umfCUDAMemoryProviderOps(),
                                  &cu_memory_provider_params,
                                  &cu_memory_provider);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to create a memory provider!\n");
        ret = -1;
        goto cuda_destroy;
    }

    printf("CUDA memory provider created at %p\n", (void *)cu_memory_provider);

    // Setup parameters for the Disjoint Pool. It will be used for managing the
    // memory allocated using memory provider.
    umf_disjoint_pool_params_t disjoint_memory_pool_params =
        umfDisjointPoolParamsDefault();
    // Set the Slab Min Size to 64KB - the page size for GPU allocations
    disjoint_memory_pool_params.SlabMinSize = 64 * 1024L;
    // We would keep only single slab per each allocation bucket
    disjoint_memory_pool_params.Capacity = 1;
    // Set the maximum poolable size to 64KB - objects with size above this
    // limit will not be stored/allocated from the pool.
    disjoint_memory_pool_params.MaxPoolableSize = 64 * 1024L;
    // Enable tracing
    disjoint_memory_pool_params.PoolTrace = 1;

    // Create Disjoint Pool memory pool.
    umf_memory_pool_handle_t cu_disjoint_memory_pool;
    res = umfPoolCreate(umfDisjointPoolOps(), cu_memory_provider,
                        &disjoint_memory_pool_params, UMF_POOL_CREATE_FLAG_NONE,
                        &cu_disjoint_memory_pool);
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

memory_provider_destroy:
    umfMemoryProviderDestroy(cu_memory_provider);

cuda_destroy:
    ret = cuCtxDestroy(cuContext);
    return ret;
}
