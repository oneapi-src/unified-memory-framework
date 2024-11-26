// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "base.hpp"

#include <umf/providers/provider_cuda.h>

using umf_test::test;

TEST_F(test, cuda_provider_not_implemented) {
    umf_cuda_memory_provider_params_handle_t hParams = nullptr;
    umf_result_t result = umfCUDAMemoryProviderParamsCreate(&hParams);
    ASSERT_EQ(result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    result = umfCUDAMemoryProviderParamsDestroy(hParams);
    ASSERT_EQ(result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    result = umfCUDAMemoryProviderParamsSetContext(hParams, nullptr);
    ASSERT_EQ(result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    result = umfCUDAMemoryProviderParamsSetDevice(hParams, 0);
    ASSERT_EQ(result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    result = umfCUDAMemoryProviderParamsSetMemoryType(hParams,
                                                      UMF_MEMORY_TYPE_DEVICE);
    ASSERT_EQ(result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    umf_memory_provider_ops_t *ops = umfCUDAMemoryProviderOps();
    ASSERT_EQ(ops, nullptr);
}
