/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <ze_api.h>

#include "umf/memory_pool.h"
#include "umf/pools/pool_disjoint.h"
#include "umf/providers/provider_level_zero.h"

ze_result_t level_zero_init(ze_driver_handle_t *driver,
                            ze_device_handle_t *device,
                            ze_context_handle_t *context) {
    // Initialize the Level Zero driver
    ze_result_t ze_result = zeInit(0);
    assert(ze_result == ZE_RESULT_SUCCESS);

    // Discover all the driver instances
    uint32_t driverCount = 0;
    ze_result = zeDriverGet(&driverCount, NULL);
    assert(ze_result == ZE_RESULT_SUCCESS);
    assert(driverCount > 0);

    ze_driver_handle_t *all_drivers =
        (ze_driver_handle_t *)calloc(driverCount, sizeof(ze_driver_handle_t));
    ze_result = zeDriverGet(&driverCount, all_drivers);
    assert(ze_result == ZE_RESULT_SUCCESS);

    // Find a driver instance with a GPU device
    for (uint32_t i = 0; i < driverCount; ++i) {
        assert(all_drivers[i] != NULL);

        uint32_t deviceCount = 0;
        ze_result = zeDeviceGet(all_drivers[i], &deviceCount, NULL);
        assert(ze_result == ZE_RESULT_SUCCESS);
        assert(deviceCount > 0);

        ze_device_handle_t *all_devices = (ze_device_handle_t *)calloc(
            deviceCount, sizeof(ze_device_handle_t));
        ze_result = zeDeviceGet(all_drivers[i], &deviceCount, all_devices);
        assert(ze_result == ZE_RESULT_SUCCESS);

        for (uint32_t d = 0; d < deviceCount; ++d) {
            assert(all_devices[d] != NULL);

            ze_device_properties_t device_properties = {0};
            device_properties.stype = ZE_STRUCTURE_TYPE_DEVICE_PROPERTIES;
            ze_result =
                zeDeviceGetProperties(all_devices[d], &device_properties);
            assert(ze_result == ZE_RESULT_SUCCESS);

            /// todo free

            if (ZE_DEVICE_TYPE_GPU == device_properties.type) {
                *driver = all_drivers[i];
                *device = all_devices[d];
                break;
            }
        }

        if (NULL != driver) {
            break;
        }
    }

    if (NULL == device) {
        // todo
        // GTEST_SKIP() << "Test skipped, no GPU devices found";
    }

    // Create context
    ze_context_desc_t ctxtDesc = {ZE_STRUCTURE_TYPE_CONTEXT_DESC, NULL, 0};
    ze_result = zeContextCreate(*driver, &ctxtDesc, context);
    assert(ze_result == ZE_RESULT_SUCCESS);
    assert(*context != NULL);

    return ze_result;
}

int main(void) {

    // A result object for storing UMF API result status
    umf_result_t res;

    // Initialize Level Zero
    ze_driver_handle_t hDriver;
    ze_device_handle_t hDevice;
    ze_context_handle_t hContext;
    level_zero_init(&hDriver, &hDevice, &hContext);

    // todo explain + why
    level_zero_memory_provider_params_t ze_memory_provider_params;
    ze_memory_provider_params.level_zero_context_handle = hContext;
    ze_memory_provider_params.level_zero_device_handle = hDevice;
    ze_memory_provider_params.memory_type = UMF_MEMORY_TYPE_SHARED;

    umf_memory_provider_handle_t ze_memory_provider;
    res = umfMemoryProviderCreate(umfLevelZeroMemoryProviderOps(),
                                  &ze_memory_provider_params,
                                  &ze_memory_provider);
    if (res != UMF_RESULT_SUCCESS) {
        printf("Failed to create a memory provider!");
        return -1;
    }
    printf("Level Zero memory provider created at %p\n",
           (void *)ze_memory_provider);

    // TODO
    umf_disjoint_pool_params_t disjoint_memory_pool_params =
        umfDisjointPoolParamsDefault();
    disjoint_memory_pool_params.SlabMinSize = 64 * 1024L;
    disjoint_memory_pool_params.Capacity = 1;
    disjoint_memory_pool_params.MaxPoolableSize = 64 * 1024L;
    disjoint_memory_pool_params.PoolTrace = 1;

    umf_memory_pool_handle_t ze_disjoint_memory_pool;
    res = umfPoolCreate(umfDisjointPoolOps(), ze_memory_provider,
                        &disjoint_memory_pool_params, UMF_POOL_CREATE_FLAG_NONE,
                        &ze_disjoint_memory_pool);
    if (res != UMF_RESULT_SUCCESS) {
        printf("Failed to create a memory pool!");
        goto memory_provider_destroy;
    }

    void *ptr = umfPoolMalloc(ze_disjoint_memory_pool, sizeof(int));
    if (res != UMF_RESULT_SUCCESS) {
        printf("Failed to allocate memory from the memory pool!");
        goto memory_pool_destroy;
    }

    // Use allocated memory
    *(int *)ptr = 1;

    // Free allocated memory
    res = umfFree(ptr);
    if (res != UMF_RESULT_SUCCESS) {
        printf("Failed to free memory to the pool!");
        goto memory_provider_destroy;
    }
    printf("Freed memory at %p\n", ptr);

    umfPoolDestroy(ze_disjoint_memory_pool);
    umfMemoryProviderDestroy(ze_memory_provider);
    return 0;

memory_pool_destroy:
    umfPoolDestroy(ze_disjoint_memory_pool);

memory_provider_destroy:
    umfMemoryProviderDestroy(ze_memory_provider);
    return -1;

    // todo free(all_drivers);
}
