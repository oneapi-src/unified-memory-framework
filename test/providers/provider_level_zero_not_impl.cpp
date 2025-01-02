// Copyright (C) 2024-2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "base.hpp"

#include <umf/providers/provider_level_zero.h>

using umf_test::test;

TEST_F(test, level_zero_provider_not_implemented) {
    umf_level_zero_memory_provider_params_handle_t hParams = nullptr;
    umf_result_t result = umfLevelZeroMemoryProviderParamsCreate(&hParams);
    ASSERT_EQ(result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    result = umfLevelZeroMemoryProviderParamsDestroy(hParams);
    ASSERT_EQ(result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    result = umfLevelZeroMemoryProviderParamsSetContext(hParams, nullptr);
    ASSERT_EQ(result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    result = umfLevelZeroMemoryProviderParamsSetDevice(hParams, nullptr);
    ASSERT_EQ(result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    result = umfLevelZeroMemoryProviderParamsSetMemoryType(
        hParams, UMF_MEMORY_TYPE_DEVICE);
    ASSERT_EQ(result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    ze_device_handle_t hDevices[1];
    result = umfLevelZeroMemoryProviderParamsSetResidentDevices(hParams,
                                                                hDevices, 1);
    ASSERT_EQ(result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    result = umfLevelZeroMemoryProviderParamsSetFreePolicy(
        hParams, UMF_LEVEL_ZERO_MEMORY_PROVIDER_FREE_POLICY_DEFAULT);
    ASSERT_EQ(result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    result = umfLevelZeroMemoryProviderParamsSetDeviceOrdinal(hParams, 0);
    ASSERT_EQ(result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    umf_memory_provider_ops_t *ops = umfLevelZeroMemoryProviderOps();
    ASSERT_EQ(ops, nullptr);
}
