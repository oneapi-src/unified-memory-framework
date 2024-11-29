/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>

#include <umf/pools/pool_disjoint.h>
#include <umf/providers/provider_level_zero.h>

#include "ipc_common.h"
#include "ipc_level_zero_prov_common.h"
#include "utils_level_zero.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        return -1;
    }

    int port = atoi(argv[1]);
    uint32_t driver_idx = 0;
    ze_driver_handle_t hDriver = NULL;
    ze_device_handle_t hDevice = NULL;
    ze_context_handle_t hContext = NULL;

    int ret = utils_ze_find_driver_with_gpu(&driver_idx, &hDriver);
    if (ret != 0 || hDriver == NULL) {
        fprintf(stderr, "utils_ze_find_driver_with_gpu() failed!\n");
        return -1;
    }

    ret = utils_ze_find_gpu_device(hDriver, &hDevice);
    if (ret != 0 || hDevice == NULL) {
        fprintf(stderr, "utils_ze_find_gpu_device() failed!\n");
        return -1;
    }

    ret = utils_ze_create_context(hDriver, &hContext);
    if (ret != 0) {
        fprintf(stderr, "utils_ze_create_context() failed!\n");
        return -1;
    }

    umf_level_zero_memory_provider_params_handle_t l0_params = NULL;
    umf_result_t umf_result =
        umfLevelZeroMemoryProviderParamsCreate(&l0_params);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "Failed to create Level Zero Memory Provider params!\n");
        ret = -1;
        goto destroy_context;
    }

    umf_result =
        umfLevelZeroMemoryProviderParamsSetContext(l0_params, hContext);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(
            stderr,
            "Failed to set context in Level Zero Memory Provider params!\n");
        ret = -1;
        goto destroy_provider_params;
    }

    umf_result = umfLevelZeroMemoryProviderParamsSetDevice(l0_params, hDevice);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "Failed to set device in Level Zero Memory Provider params!\n");
        ret = -1;
        goto destroy_provider_params;
    }

    umf_result = umfLevelZeroMemoryProviderParamsSetMemoryType(
        l0_params, UMF_MEMORY_TYPE_DEVICE);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to set memory type in Level Zero Memory "
                        "Provider params!\n");
        ret = -1;
        goto destroy_provider_params;
    }

    umf_disjoint_pool_params_handle_t pool_params = NULL;

    umf_result = umfDisjointPoolParamsCreate(&pool_params);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to create pool params!\n");
        ret = -1;
        goto destroy_provider_params;
    }

    level_zero_copy_ctx_t copy_ctx = {hContext, hDevice};

    ret = run_consumer(port, umfDisjointPoolOps(), pool_params,
                       umfLevelZeroMemoryProviderOps(), l0_params, memcopy,
                       &copy_ctx);

    umfDisjointPoolParamsDestroy(pool_params);

destroy_provider_params:
    umfLevelZeroMemoryProviderParamsDestroy(l0_params);

destroy_context:
    utils_ze_destroy_context(hContext);

    return ret;
}
