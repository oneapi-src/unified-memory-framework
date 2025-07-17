/*
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include "provider_props.hpp"
#include "utils/utils_level_zero.h"

void levelZeroMemoryProviderCreate(umf_memory_provider_handle_t *out_provider,
                                   void *out_data) {

    ze_driver_handle_t hDriver = nullptr;
    ze_device_handle_t hDevice = nullptr;
    ze_context_handle_t hContext = nullptr;
    uint32_t driver_idx = 0;

    int ret = utils_ze_init_level_zero();
    ASSERT_EQ(ret, 0);

    ret = utils_ze_find_driver_with_gpu(&driver_idx, &hDriver);
    ASSERT_EQ(ret, 0);

    ret = utils_ze_find_gpu_device(hDriver, &hDevice);
    ASSERT_EQ(ret, 0);

    ret = utils_ze_create_context(hDriver, &hContext);
    ASSERT_EQ(ret, 0);

    umf_level_zero_memory_provider_params_handle_t params = nullptr;
    umf_result_t result = umfLevelZeroMemoryProviderParamsCreate(&params);
    ASSERT_EQ(result, UMF_RESULT_SUCCESS);
    result = umfLevelZeroMemoryProviderParamsSetContext(params, hContext);
    ASSERT_EQ(result, UMF_RESULT_SUCCESS);
    result = umfLevelZeroMemoryProviderParamsSetDevice(params, hDevice);
    ASSERT_EQ(result, UMF_RESULT_SUCCESS);
    result = umfLevelZeroMemoryProviderParamsSetMemoryType(
        params, UMF_MEMORY_TYPE_DEVICE);
    ASSERT_EQ(result, UMF_RESULT_SUCCESS);

    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t umf_result = umfMemoryProviderCreate(
        umfLevelZeroMemoryProviderOps(), params, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    result = umfLevelZeroMemoryProviderParamsDestroy(params);
    ASSERT_EQ(result, UMF_RESULT_SUCCESS);

    *out_provider = provider;
    *(uintptr_t *)out_data = (uintptr_t)hContext;
}

void levelZeroMemoryProviderDestroy(umf_memory_provider_handle_t provider,
                                    void *data) {
    umfMemoryProviderDestroy(provider);
    utils_ze_destroy_context((ze_context_handle_t)data);
}

INSTANTIATE_TEST_SUITE_P(providerPropsTest, ProviderPropsTest,
                         ::testing::Values(testParams{
                             levelZeroMemoryProviderCreate,
                             levelZeroMemoryProviderDestroy,
                             "levelZeroProvider"}),
                         nameGen);
