/*
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <umf/pools/pool_proxy.h>

#include "memory_props_internal.h"
#include "provider.hpp"
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

TEST_F(test, CustomPropsTest) {
    const uint64_t custom_property_id = UMF_MEMORY_PROPERTY_MAX_RESERVED + 1;

    struct memory_provider : public umf_test::provider_base_t {
        umf_result_t alloc(size_t size, size_t alignment, void **ptr) noexcept {
            *ptr = umf_ba_global_aligned_alloc(size, alignment);
            return UMF_RESULT_SUCCESS;
        }

        umf_result_t free(void *ptr, [[maybe_unused]] size_t size) noexcept {
            umf_ba_global_free(ptr);
            return UMF_RESULT_SUCCESS;
        }

        umf_result_t
        get_min_page_size([[maybe_unused]] const void *ptr,
                          [[maybe_unused]] size_t *pageSize) noexcept {
            *pageSize = 1024;
            return UMF_RESULT_SUCCESS;
        }

        umf_result_t ext_get_allocation_properties(
            const void *ptr, umf_memory_property_id_t memory_property_id,
            void *value, size_t max_property_size) {

            (void)ptr; // unused

            if (memory_property_id == custom_property_id) {
                if (max_property_size < sizeof(uint64_t)) {
                    return UMF_RESULT_ERROR_INVALID_ARGUMENT;
                }
                *(uint64_t *)value = 42; // Custom value for the property
                return UMF_RESULT_SUCCESS;
            }

            return umf_test::provider_base_t::ext_get_allocation_properties(
                ptr, memory_property_id, value, max_property_size);
        }
    };

    umf_memory_provider_ops_t provider_ops =
        umf_test::providerMakeCOps<memory_provider, void>();

    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t res =
        umfMemoryProviderCreate(&provider_ops, nullptr, &provider);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    umf_memory_pool_handle_t pool = nullptr;
    res = umfPoolCreate(umfProxyPoolOps(), provider, nullptr,
                        UMF_POOL_CREATE_FLAG_NONE, &pool);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    ASSERT_NE(pool, nullptr);

    void *ptr = umfPoolMalloc(pool, 1024);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    umf_memory_properties_handle_t properties = nullptr;
    res = umfGetMemoryPropertiesHandle(ptr, &properties);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    ASSERT_NE(properties, nullptr);

    // get value of the custom property from the properties handle
    uint64_t value2 = 0;
    res = umfGetMemoryProperty(properties,
                               (umf_memory_property_id_t)custom_property_id,
                               sizeof(value2), &value2);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    ASSERT_EQ(value2, 42);

    res = umfPoolFree(pool, ptr);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);

    res = umfPoolDestroy(pool);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);

    res = umfMemoryProviderDestroy(provider);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
}
