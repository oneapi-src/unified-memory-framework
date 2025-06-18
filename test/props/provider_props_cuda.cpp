/*
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include "provider_props.hpp"
#include "providers/cuda_helpers.h"

void createCudaMemoryProvider(umf_memory_provider_handle_t *out_provider,
                              void *out_data) {
    CUdevice hDevice = -1;
    CUcontext hContext = NULL;

    int ret = init_cuda();
    ASSERT_EQ(ret, 0);

    ret = get_cuda_device(&hDevice);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(hDevice, -1);

    ret = create_context(hDevice, &hContext);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(hContext, nullptr);

    umf_cuda_memory_provider_params_handle_t cu_params = NULL;
    umf_result_t umf_result = umfCUDAMemoryProviderParamsCreate(&cu_params);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(cu_params, nullptr);

    umf_result = umfCUDAMemoryProviderParamsSetContext(cu_params, hContext);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result = umfCUDAMemoryProviderParamsSetDevice(cu_params, hDevice);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result = umfCUDAMemoryProviderParamsSetMemoryType(
        cu_params, UMF_MEMORY_TYPE_DEVICE);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_memory_provider_handle_t provider = nullptr;
    umf_result = umfMemoryProviderCreate(umfCUDAMemoryProviderOps(), cu_params,
                                         &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    umfCUDAMemoryProviderParamsDestroy(cu_params);

    *out_provider = provider;
    *(uintptr_t *)out_data = (uintptr_t)hContext;
}

void destroyCudaMemoryProvider(umf_memory_provider_handle_t provider,
                               void *data) {
    destroy_context((CUcontext)data);
    umfMemoryProviderDestroy(provider);
}

INSTANTIATE_TEST_SUITE_P(providerPropsTest, ProviderPropsTest,
                         ::testing::Values(testParams{createCudaMemoryProvider,
                                                      destroyCudaMemoryProvider,
                                                      "cudaMemoryProvider"}),
                         nameGen);
