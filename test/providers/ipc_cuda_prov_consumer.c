/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>

#include <umf/pools/pool_disjoint.h>
#include <umf/providers/provider_cuda.h>

#include "cuda_helpers.h"
#include "ipc_common.h"
#include "ipc_cuda_prov_common.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        return -1;
    }

    int port = atoi(argv[1]);
    CUdevice hDevice = -1;
    CUcontext hContext = NULL;

    int ret = get_cuda_device(&hDevice);
    if (ret != 0) {
        fprintf(stderr, "get_cuda_device() failed!\n");
        return -1;
    }

    ret = create_context(hDevice, &hContext);
    if (ret != 0) {
        fprintf(stderr, "create_context() failed!\n");
        return -1;
    }

    umf_cuda_memory_provider_params_handle_t cu_params = NULL;
    umf_result_t umf_result = umfCUDAMemoryProviderParamsCreate(&cu_params);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to create CUDA params!\n");
        ret = -1;
        goto destroy_context;
    }

    umf_result = umfCUDAMemoryProviderParamsSetContext(cu_params, hContext);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "Failed to set context in CUDA Memory Provider params!\n");
        ret = -1;
        goto destroy_provider_params;
    }

    umf_result = umfCUDAMemoryProviderParamsSetDevice(cu_params, hDevice);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "Failed to set device in CUDA Memory Provider params!\n");
        ret = -1;
        goto destroy_provider_params;
    }

    umf_result = umfCUDAMemoryProviderParamsSetMemoryType(
        cu_params, UMF_MEMORY_TYPE_DEVICE);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to set memory type in CUDA memory "
                        "provider params!\n");
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

    cuda_copy_ctx_t copy_ctx = {hContext, hDevice};

    ret =
        run_consumer(port, umfDisjointPoolOps(), pool_params,
                     umfCUDAMemoryProviderOps(), cu_params, memcopy, &copy_ctx);

    umfDisjointPoolParamsDestroy(pool_params);

destroy_provider_params:
    umfCUDAMemoryProviderParamsDestroy(cu_params);

destroy_context:
    destroy_context(hContext);

    return ret;
}
