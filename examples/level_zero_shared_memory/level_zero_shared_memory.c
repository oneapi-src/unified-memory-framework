/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <umf/memory_pool.h>
#include <umf/pools/pool_disjoint.h>
#include <umf/providers/provider_level_zero.h>

#include "utils_level_zero.h"

int main(void) {
    // A result object for storing UMF API result status
    umf_result_t res;

    uint32_t driverId = 0;
    ze_driver_handle_t hDriver = NULL;
    ze_device_handle_t hDevice = NULL;
    ze_context_handle_t hContext = NULL;

    // Initialize Level Zero
    int ret = init_level_zero();
    if (ret != 0) {
        fprintf(stderr, "Failed to init Level 0!\n");
        return ret;
    }

    ret = find_driver_with_gpu(&driverId, &hDriver);
    if (ret || hDriver == NULL) {
        fprintf(stderr, "Cannot find L0 driver with GPU device!\n");
        return ret;
    }

    ret = find_gpu_device(hDriver, &hDevice);
    if (ret || hDevice == NULL) {
        fprintf(stderr, "Cannot find GPU device!\n");
        return ret;
    }

    ret = create_context(hDriver, &hContext);
    if (ret != 0) {
        fprintf(stderr, "Failed to create L0 context!\n");
        return ret;
    }

    // Setup parameters for the Level Zero memory provider. It will be used for
    // allocating memory from Level Zero devices.
    level_zero_memory_provider_params_t ze_memory_provider_params = {0};
    ze_memory_provider_params.level_zero_context_handle = hContext;
    ze_memory_provider_params.level_zero_device_handle = hDevice;
    // Set the memory type to shared to allow the memory to be accessed on both
    // CPU and GPU.
    ze_memory_provider_params.memory_type = UMF_MEMORY_TYPE_SHARED;

    // Create Level Zero memory provider
    umf_memory_provider_handle_t ze_memory_provider;
    res = umfMemoryProviderCreate(umfLevelZeroMemoryProviderOps(),
                                  &ze_memory_provider_params,
                                  &ze_memory_provider);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to create a memory provider!\n");
        ret = -1;
        goto level_zero_destroy;
    }

    printf("Level Zero memory provider created at %p\n",
           (void *)ze_memory_provider);

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
    umf_memory_pool_handle_t ze_disjoint_memory_pool;
    res = umfPoolCreate(umfDisjointPoolOps(), ze_memory_provider,
                        &disjoint_memory_pool_params, UMF_POOL_CREATE_FLAG_NONE,
                        &ze_disjoint_memory_pool);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to create a memory pool!\n");
        ret = -1;
        goto memory_provider_destroy;
    }

    printf("Disjoint Pool created at %p\n", (void *)ze_disjoint_memory_pool);

    // Allocate some memory from the pool
    int *ptr = umfPoolMalloc(ze_disjoint_memory_pool, sizeof(int));
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
    umfPoolDestroy(ze_disjoint_memory_pool);

memory_provider_destroy:
    umfMemoryProviderDestroy(ze_memory_provider);

level_zero_destroy:
    ret = destroy_context(hContext);
    return ret;
}
