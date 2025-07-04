/*
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include "provider_props.hpp"

void createFixedProvider(umf_memory_provider_handle_t *out_provider,
                         void *out_data) {
    constexpr size_t buffer_size = 1024 * 1024;

    void *memory_buffer = malloc(buffer_size);
    ASSERT_NE(memory_buffer, nullptr);

    umf_fixed_memory_provider_params_handle_t params = nullptr;
    umf_result_t res =
        umfFixedMemoryProviderParamsCreate(memory_buffer, buffer_size, &params);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    ASSERT_NE(params, nullptr);

    res = umfMemoryProviderCreate(umfFixedMemoryProviderOps(), params,
                                  out_provider);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    ASSERT_NE(out_provider, nullptr);

    umfFixedMemoryProviderParamsDestroy(params);

    *(uintptr_t *)out_data = (uintptr_t)memory_buffer;
}

void destroyFixedProvider(umf_memory_provider_handle_t provider, void *data) {
    umfMemoryProviderDestroy(provider);
    free(data);
}

void createOsMemoryProvider(umf_memory_provider_handle_t *out_provider,
                            void *out_data) {

    umf_os_memory_provider_params_handle_t os_memory_provider_params = nullptr;
    umf_result_t res =
        umfOsMemoryProviderParamsCreate(&os_memory_provider_params);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    ASSERT_NE(os_memory_provider_params, nullptr);

    umf_memory_provider_handle_t os_memory_provider = nullptr;
    res =
        umfMemoryProviderCreate(umfOsMemoryProviderOps(),
                                os_memory_provider_params, &os_memory_provider);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    ASSERT_NE(os_memory_provider, nullptr);

    res = umfOsMemoryProviderParamsDestroy(os_memory_provider_params);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);

    *out_provider = os_memory_provider;
    *(uintptr_t *)out_data = (uintptr_t)NULL;
}

void destroyOsMemoryProvider(umf_memory_provider_handle_t provider,
                             void *data) {
    (void)data; // unused

    umfMemoryProviderDestroy(provider);
}

INSTANTIATE_TEST_SUITE_P(
    providerPropsTest, ProviderPropsTest,
    ::testing::Values(testParams{createFixedProvider, destroyFixedProvider,
                                 "fixedProvider"},
                      testParams{createOsMemoryProvider,
                                 destroyOsMemoryProvider, "osMemoryProvider"}),
    nameGen);
