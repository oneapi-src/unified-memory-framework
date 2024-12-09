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

#include "umf/ipc.h"
#include "umf/memory_pool.h"
#include "umf/pools/pool_disjoint.h"
#include "umf/providers/provider_level_zero.h"

#include "examples_level_zero_helpers.h"

int create_level_zero_pool(ze_context_handle_t context,
                           ze_device_handle_t device,
                           umf_memory_pool_handle_t *pool) {
    // setup params
    umf_level_zero_memory_provider_params_handle_t provider_params = NULL;

    umf_result_t umf_result =
        umfLevelZeroMemoryProviderParamsCreate(&provider_params);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "ERROR: Failed to create Level Zero memory provider params!\n");
        return -1;
    }

    umf_result =
        umfLevelZeroMemoryProviderParamsSetContext(provider_params, context);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to set context in Level Zero memory "
                        "provider params!\n");
        umfLevelZeroMemoryProviderParamsDestroy(provider_params);
        return -1;
    }

    umf_result =
        umfLevelZeroMemoryProviderParamsSetDevice(provider_params, device);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to set device in Level Zero memory "
                        "provider params!\n");
        umfLevelZeroMemoryProviderParamsDestroy(provider_params);
        return -1;
    }

    umf_result = umfLevelZeroMemoryProviderParamsSetMemoryType(
        provider_params, UMF_MEMORY_TYPE_DEVICE);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to set memory type in Level Zero memory "
                        "provider params!\n");
        umfLevelZeroMemoryProviderParamsDestroy(provider_params);
        return -1;
    }

    // create Level Zero provider
    umf_memory_provider_handle_t provider = 0;
    umf_result = umfMemoryProviderCreate(umfLevelZeroMemoryProviderOps(),
                                         provider_params, &provider);
    umfLevelZeroMemoryProviderParamsDestroy(provider_params);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "ERROR: Failed to create Level Zero memory provider!\n");
        return -1;
    }

    umf_disjoint_pool_params_handle_t disjoint_params = NULL;
    umf_result = umfDisjointPoolParamsCreate(&disjoint_params);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to create pool params!\n");
        goto provider_destroy;
    }

    // create pool
    umf_pool_create_flags_t flags = UMF_POOL_CREATE_FLAG_OWN_PROVIDER;
    umf_result = umfPoolCreate(umfDisjointPoolOps(), provider, disjoint_params,
                               flags, pool);
    umfDisjointPoolParamsDestroy(disjoint_params);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to create pool!\n");
        goto provider_destroy;
    }

    return 0;

provider_destroy:
    umfMemoryProviderDestroy(provider);

    return -1;
}

int main(void) {
    uint32_t driver_idx = 0;
    ze_driver_handle_t driver = NULL;
    ze_device_handle_t device = NULL;
    ze_context_handle_t producer_context = NULL;
    ze_context_handle_t consumer_context = NULL;
    const size_t BUFFER_SIZE = 1024;
    const size_t BUFFER_PATTERN = 0x42;
    int ret = init_level_zero();
    if (ret != 0) {
        fprintf(stderr, "ERROR: Failed to init Level 0!\n");
        return ret;
    }

    ret = find_driver_with_gpu(&driver_idx, &driver);
    if (ret || driver == NULL) {
        fprintf(stderr, "ERROR: Cannot find L0 driver with GPU device!\n");
        return ret;
    }

    ret = create_context(driver, &producer_context);
    if (ret != 0) {
        fprintf(stderr, "ERROR: Failed to create L0 context!\n");
        return ret;
    }

    ret = create_context(driver, &consumer_context);
    if (ret != 0) {
        fprintf(stderr, "ERROR: Failed to create L0 context!\n");
        return ret;
    }

    ret = find_gpu_device(driver, &device);
    if (ret || device == NULL) {
        fprintf(stderr, "ERROR: Cannot find GPU device!\n");
        return ret;
    }

    // create producer pool
    umf_memory_pool_handle_t producer_pool = 0;
    ret = create_level_zero_pool(producer_context, device, &producer_pool);
    if (ret != 0) {
        fprintf(stderr, "ERROR: Failed to create producer pool!\n");
        return ret;
    }

    fprintf(stdout, "Producer pool created.\n");

    void *initial_buf = umfPoolMalloc(producer_pool, BUFFER_SIZE);
    if (!initial_buf) {
        fprintf(stderr, "ERROR: Failed to allocate buffer from UMF pool!\n");
        return -1;
    }

    fprintf(stdout, "Buffer allocated from the producer pool.\n");

    ret = level_zero_fill(producer_context, device, initial_buf, BUFFER_SIZE,
                          &BUFFER_PATTERN, sizeof(BUFFER_PATTERN));
    if (ret != 0) {
        fprintf(stderr, "ERROR: Failed to fill the buffer with pattern!\n");
        return ret;
    }

    fprintf(stdout, "Buffer filled with pattern.\n");

    umf_ipc_handle_t ipc_handle = NULL;
    size_t handle_size = 0;
    umf_result_t umf_result =
        umfGetIPCHandle(initial_buf, &ipc_handle, &handle_size);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to get IPC handle!\n");
        return -1;
    }

    fprintf(stdout, "IPC handle obtained.\n");

    // create consumer pool
    umf_memory_pool_handle_t consumer_pool = 0;
    ret = create_level_zero_pool(consumer_context, device, &consumer_pool);
    if (ret != 0) {
        fprintf(stderr, "ERROR: Failed to create consumer pool!\n");
        return ret;
    }

    fprintf(stdout, "Consumer pool created.\n");

    umf_ipc_handler_handle_t ipc_handler = 0;
    umf_result = umfPoolGetIPCHandler(consumer_pool, &ipc_handler);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to get IPC handler!\n");
        return -1;
    }

    void *mapped_buf = NULL;
    umf_result = umfOpenIPCHandle(ipc_handler, ipc_handle, &mapped_buf);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to open IPC handle!\n");
        return -1;
    }

    fprintf(stdout, "IPC handle opened.\n");

    size_t *tmp_buf = malloc(BUFFER_SIZE);
    ret = level_zero_copy(consumer_context, device, tmp_buf, mapped_buf,
                          BUFFER_SIZE);
    if (ret != 0) {
        fprintf(stderr, "ERROR: Failed to copy mapped_buf to host!\n");
        return ret;
    }

    // Verify the content of the buffer
    for (size_t i = 0; i < BUFFER_SIZE / sizeof(BUFFER_PATTERN); ++i) {
        if (tmp_buf[i] != BUFFER_PATTERN) {
            fprintf(stderr, "ERROR: mapped_buf does not match initial_buf!\n");
            return -1;
        }
    }

    fprintf(stdout, "mapped_buf matches initial_buf.\n");

    umf_result = umfPutIPCHandle(ipc_handle);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to put IPC handle!\n");
        return -1;
    }

    fprintf(stdout, "IPC handle released in the producer pool.\n");

    umf_result = umfCloseIPCHandle(mapped_buf);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to close IPC handle!\n");
        return -1;
    }

    fprintf(stdout, "IPC handle closed in the consumer pool.\n");

    umfFree(initial_buf);

    umfPoolDestroy(producer_pool);
    umfPoolDestroy(consumer_pool);

    ret = destroy_context(producer_context);
    if (ret != 0) {
        fprintf(stderr, "ERROR: Failed to destroy L0 context!\n");
        return ret;
    }

    ret = destroy_context(consumer_context);
    if (ret != 0) {
        fprintf(stderr, "ERROR: Failed to destroy L0 context!\n");
        return ret;
    }
    return 0;
}
