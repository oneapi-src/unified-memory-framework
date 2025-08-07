/*
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <umf/experimental/memory_properties.h>
#include <umf/pools/pool_proxy.h>
#include <umf/providers/provider_fixed_memory.h>
#include <umf/providers/provider_os_memory.h>

#include "base.hpp"
#include "test_helpers.h"

using umf_test::test;

using testParams =
    std::tuple<std::function<void(umf_memory_provider_handle_t *, void *)>,
               std::function<void(umf_memory_provider_handle_t, void *)>,
               const char *>;

std::string nameGen(const testing::TestParamInfo<testParams> param) {
    return std::get<2>(param.param);
}

struct ProviderPropsTest : umf_test::test,
                           ::testing::WithParamInterface<testParams> {
    void SetUp() override {
        test::SetUp();

        auto [create_fun, destroy_fun, name] = this->GetParam();
        provider_create = create_fun;
        provider_destroy = destroy_fun;
        (void)name; // unused

        provider_create(&provider, &data);
        ASSERT_NE(provider, nullptr);

        umf_result_t umf_result =
            umfPoolCreate(umfProxyPoolOps(), provider, nullptr, 0, &pool);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    }

    void TearDown() override {
        umfPoolDestroy(pool);
        provider_destroy(provider, data);
        test::TearDown();
    }

    umf_memory_provider_handle_t provider;
    umf_memory_pool_handle_t pool;

    std::function<void(umf_memory_provider_handle_t *, void *)> provider_create;
    std::function<void(umf_memory_provider_handle_t, void *)> provider_destroy;
    void *data;
};

TEST_P(ProviderPropsTest, genericProps) {
    umf_result_t umf_result;
    const size_t alloc_size = 8;

    void *ptr = umfPoolMalloc(pool, alloc_size);
    ASSERT_NE(ptr, nullptr);

    umf_memory_properties_handle_t props_handle = nullptr;
    umf_result = umfGetMemoryPropertiesHandle(ptr, &props_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(props_handle, nullptr);

    umf_memory_provider_handle_t param_provider = nullptr;
    umf_result =
        umfGetMemoryProperty(props_handle, UMF_MEMORY_PROPERTY_PROVIDER_HANDLE,
                             &param_provider, sizeof(param_provider));
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(param_provider, provider);

    umf_memory_pool_handle_t param_pool = nullptr;
    umf_result =
        umfGetMemoryProperty(props_handle, UMF_MEMORY_PROPERTY_POOL_HANDLE,
                             &param_pool, sizeof(param_pool));
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(param_pool, pool);

    void *base_address = nullptr;
    umf_result =
        umfGetMemoryProperty(props_handle, UMF_MEMORY_PROPERTY_BASE_ADDRESS,
                             &base_address, sizeof(base_address));
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(base_address, ptr);

    size_t size = 0;
    umf_result = umfGetMemoryProperty(
        props_handle, UMF_MEMORY_PROPERTY_BASE_SIZE, &size, sizeof(size));
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(size, alloc_size);

    uint64_t buffer_id = 0;
    umf_result =
        umfGetMemoryProperty(props_handle, UMF_MEMORY_PROPERTY_BUFFER_ID,
                             &buffer_id, sizeof(buffer_id));
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_GE(buffer_id, 0);

    umf_result = umfPoolFree(pool, ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
}

TEST_P(ProviderPropsTest, baseAddressFromMiddle) {
    umf_result_t umf_result;
    const size_t alloc_size = 8;

    void *ptr = umfPoolMalloc(pool, alloc_size);
    ASSERT_NE(ptr, nullptr);

    void *ptr_mid = (void *)((uintptr_t)ptr + (alloc_size / 2));
    umf_memory_properties_handle_t props_handle = nullptr;
    umf_result = umfGetMemoryPropertiesHandle(ptr_mid, &props_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(props_handle, nullptr);

    uintptr_t param_base_address = 0;
    umf_result =
        umfGetMemoryProperty(props_handle, UMF_MEMORY_PROPERTY_BASE_ADDRESS,
                             &param_base_address, sizeof(param_base_address));
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(param_base_address, (uintptr_t)ptr);

    umf_result = umfPoolFree(pool, ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
}

TEST_P(ProviderPropsTest, uniqueBufferId) {
    size_t alloc_size = 8;
    size_t num_allocs = 10;
    umf_result_t umf_result;
    std::set<uint64_t> buffer_ids;

    for (size_t i = 0; i < num_allocs; ++i) {
        void *ptr = umfPoolMalloc(pool, alloc_size);
        ASSERT_NE(ptr, nullptr);

        umf_memory_properties_handle_t props_handle = nullptr;
        umf_result = umfGetMemoryPropertiesHandle(ptr, &props_handle);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        ASSERT_NE(props_handle, nullptr);

        uint64_t buffer_id = 0;
        umf_result =
            umfGetMemoryProperty(props_handle, UMF_MEMORY_PROPERTY_BUFFER_ID,
                                 &buffer_id, sizeof(buffer_id));
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        ASSERT_GE(buffer_id, 0);

        // Ensure that the buffer ID is unique by inserting it into a set and
        // checking if it was already present
        ASSERT_TRUE(buffer_ids.find(buffer_id) == buffer_ids.end());
        ASSERT_TRUE(buffer_ids.insert(buffer_id).second);

        umf_result = umfPoolFree(pool, ptr);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    }
}

// Negative tests

TEST_P(ProviderPropsTest, invalidPointer) {
    umf_memory_properties_handle_t props_handle = nullptr;
    umf_result_t umf_result =
        umfGetMemoryPropertiesHandle(nullptr, &props_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(props_handle, nullptr);

    uintptr_t invalid_ptr = 0xdeadbeef;
    umf_result =
        umfGetMemoryPropertiesHandle((void *)invalid_ptr, &props_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(props_handle, nullptr);
}

TEST_P(ProviderPropsTest, invalidPropertyId) {
    void *ptr = umfPoolMalloc(pool, 8);
    ASSERT_NE(ptr, nullptr);

    umf_memory_properties_handle_t props_handle = nullptr;
    umf_result_t res = umfGetMemoryPropertiesHandle(ptr, &props_handle);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    ASSERT_NE(props_handle, nullptr);

    void *value = nullptr;
    res = umfGetMemoryProperty(props_handle, UMF_MEMORY_PROPERTY_INVALID,
                               &value, sizeof(value));
    ASSERT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfPoolFree(pool, ptr);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
}

TEST_P(ProviderPropsTest, invalidPropertyValue) {
    void *ptr = umfPoolMalloc(pool, 8);
    ASSERT_NE(ptr, nullptr);

    umf_memory_properties_handle_t props_handle = nullptr;
    umf_result_t res = umfGetMemoryPropertiesHandle(ptr, &props_handle);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    ASSERT_NE(props_handle, nullptr);

    res = umfGetMemoryProperty(props_handle, UMF_MEMORY_PROPERTY_BASE_ADDRESS,
                               NULL, sizeof(int));
    ASSERT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfPoolFree(pool, ptr);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
}

TEST_P(ProviderPropsTest, invalidPropertySize) {
    void *ptr = umfPoolMalloc(pool, 8);
    ASSERT_NE(ptr, nullptr);

    umf_memory_properties_handle_t props_handle = nullptr;
    umf_result_t res = umfGetMemoryPropertiesHandle(ptr, &props_handle);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    ASSERT_NE(props_handle, nullptr);

    int value = 0;
    res = umfGetMemoryProperty(props_handle, UMF_MEMORY_PROPERTY_BASE_ADDRESS,
                               &value, size_t(0));
    ASSERT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfPoolFree(pool, ptr);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
}

TEST_P(ProviderPropsTest, nullPropertiesHandle) {
    int val = 0;
    umf_result_t res = umfGetMemoryProperty(
        NULL, UMF_MEMORY_PROPERTY_BASE_ADDRESS, &val, sizeof(val));
    ASSERT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}
