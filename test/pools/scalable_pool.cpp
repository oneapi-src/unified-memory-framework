// Copyright (C) 2023-2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <umf/pools/pool_scalable.h>
#include <umf/providers/provider_os_memory.h>

#include "pool.hpp"
#include "poolFixtures.hpp"
#include "provider.hpp"

void *createOsMemoryProviderParams() {
    umf_os_memory_provider_params_handle_t params = nullptr;
    umf_result_t res = umfOsMemoryProviderParamsCreate(&params);
    if (res != UMF_RESULT_SUCCESS) {
        throw std::runtime_error("Failed to create os memory provider params");
    }

    return params;
}

umf_result_t destroyOsMemoryProviderParams(void *params) {
    return umfOsMemoryProviderParamsDestroy(
        (umf_os_memory_provider_params_handle_t)params);
}

INSTANTIATE_TEST_SUITE_P(
    scalablePoolTest, umfPoolTest,
    ::testing::Values(poolCreateExtParams{
        umfScalablePoolOps(), nullptr, nullptr, umfOsMemoryProviderOps(),
        createOsMemoryProviderParams, destroyOsMemoryProviderParams}),
    poolCreateExtParamsNameGen);

using scalablePoolParams = std::tuple<size_t, bool>;
struct umfScalablePoolParamsTest
    : umf_test::test,
      ::testing::WithParamInterface<scalablePoolParams> {

    struct validation_params_t {
        size_t granularity;
        bool keep_all_memory;
    };

    struct provider_validator : public umf_test::provider_ba_global {
        using base_provider = umf_test::provider_ba_global;

        umf_result_t initialize(const validation_params_t *params) {
            EXPECT_NE(params, nullptr);
            expected_params = params;
            return UMF_RESULT_SUCCESS;
        }
        umf_result_t alloc(size_t size, size_t align, void **ptr) {
            EXPECT_EQ(size, expected_params->granularity);
            return base_provider::alloc(size, align, ptr);
        }
        umf_result_t free(void *ptr, size_t size) {
            EXPECT_EQ(expected_params->keep_all_memory, false);
            return base_provider::free(ptr, size);
        }

        const validation_params_t *expected_params;
    };

    static constexpr umf_memory_provider_ops_t VALIDATOR_PROVIDER_OPS =
        umf_test::providerMakeCOps<provider_validator, validation_params_t>();

    umfScalablePoolParamsTest() : expected_params{0, false}, params(nullptr) {}
    void SetUp() override {
        test::SetUp();
        auto [granularity, keep_all_memory] = this->GetParam();
        expected_params.granularity = granularity;
        expected_params.keep_all_memory = keep_all_memory;
        umf_result_t ret = umfScalablePoolParamsCreate(&params);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        ret = umfScalablePoolParamsSetGranularity(params, granularity);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        ret = umfScalablePoolParamsSetKeepAllMemory(params, keep_all_memory);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    }

    void TearDown() override {
        umfScalablePoolParamsDestroy(params);
        test::TearDown();
    }

    umf_test::pool_unique_handle_t makePool() {
        umf_memory_provider_handle_t hProvider = nullptr;
        umf_memory_pool_handle_t hPool = nullptr;

        auto ret = umfMemoryProviderCreate(&VALIDATOR_PROVIDER_OPS,
                                           &expected_params, &hProvider);
        EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

        ret = umfPoolCreate(umfScalablePoolOps(), hProvider, params,
                            UMF_POOL_CREATE_FLAG_OWN_PROVIDER, &hPool);
        EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

        return umf_test::pool_unique_handle_t(hPool, &umfPoolDestroy);
    }

    void allocFreeFlow() {
        static const size_t ALLOC_SIZE = 128;
        static const size_t NUM_ALLOCATIONS =
            expected_params.granularity / ALLOC_SIZE * 20;
        std::vector<void *> ptrs;

        auto pool = makePool();
        ASSERT_NE(pool, nullptr);

        for (size_t i = 0; i < NUM_ALLOCATIONS; ++i) {
            auto *ptr = umfPoolMalloc(pool.get(), ALLOC_SIZE);
            ASSERT_NE(ptr, nullptr);
            ptrs.push_back(ptr);
        }

        for (size_t i = 0; i < NUM_ALLOCATIONS; ++i) {
            auto ret = umfPoolFree(pool.get(), ptrs[i]);
            ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        }

        // Now pool can call free during pool destruction
        expected_params.keep_all_memory = false;
    }

    validation_params_t expected_params;
    umf_scalable_pool_params_handle_t params;
};

TEST_P(umfScalablePoolParamsTest, allocFree) { allocFreeFlow(); }

TEST_P(umfScalablePoolParamsTest, updateParams) {
    expected_params.granularity *= 2;
    umf_result_t ret = umfScalablePoolParamsSetGranularity(
        params, expected_params.granularity);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    expected_params.keep_all_memory = !expected_params.keep_all_memory;
    ret = umfScalablePoolParamsSetKeepAllMemory(
        params, expected_params.keep_all_memory);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    allocFreeFlow();
}

TEST_P(umfScalablePoolParamsTest, invalidParams) {
    umf_result_t ret = umfScalablePoolParamsCreate(nullptr);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = umfScalablePoolParamsSetGranularity(nullptr, 2 * 1024 * 1024);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = umfScalablePoolParamsSetGranularity(params, 0);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = umfScalablePoolParamsSetKeepAllMemory(nullptr, true);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = umfScalablePoolParamsSetKeepAllMemory(nullptr, false);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = umfScalablePoolParamsDestroy(nullptr);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

INSTANTIATE_TEST_SUITE_P(
    scalablePoolTest, umfScalablePoolParamsTest,
    testing::Combine(testing::Values(2 * 1024 * 1024, 3 * 1024 * 1024,
                                     4 * 1024 * 1024, 5 * 1024 * 1024),
                     testing::Values(false, true)),
    ([](auto const &info) -> std::string {
        return "scalable_granularity_" +
               std::to_string(std::get<0>(info.param)) + "_keep_all_memory" +
               (std::get<1>(info.param) ? "_true" : "_false");
    }));

TEST(scalablePoolTest, scalablePoolName) {
    umf_memory_pool_handle_t pool = nullptr;
    umf_os_memory_provider_params_handle_t provider_params = nullptr;
    umf_memory_provider_handle_t provider = nullptr;

    umf_result_t ret = umfOsMemoryProviderParamsCreate(&provider_params);
    ret = umfMemoryProviderCreate(umfOsMemoryProviderOps(), provider_params,
                                  &provider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfPoolCreate(umfScalablePoolOps(), provider, nullptr, 0, &pool);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    const char *name = nullptr;
    ret = umfPoolGetName(pool, &name);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    EXPECT_STREQ(name, "scalable");

    umfPoolDestroy(pool);
    umfMemoryProviderDestroy(provider);
    umfOsMemoryProviderParamsDestroy(provider_params);
}

TEST(scalablePoolTest, scalablePoolCustomName) {
    umf_memory_pool_handle_t pool = nullptr;
    umf_os_memory_provider_params_handle_t provider_params = nullptr;
    umf_memory_provider_handle_t provider = nullptr;

    auto ret = umfOsMemoryProviderParamsCreate(&provider_params);
    ret = umfMemoryProviderCreate(umfOsMemoryProviderOps(), provider_params,
                                  &provider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    umf_scalable_pool_params_handle_t params = nullptr;
    ret = umfScalablePoolParamsCreate(&params);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(umfScalablePoolParamsSetName(params, "custom_scalable"),
              UMF_RESULT_SUCCESS);

    ret = umfPoolCreate(umfScalablePoolOps(), provider, params, 0, &pool);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    const char *name = nullptr;
    ret = umfPoolGetName(pool, &name);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    EXPECT_STREQ(name, "custom_scalable");

    umfPoolDestroy(pool);
    umfScalablePoolParamsDestroy(params);
    umfMemoryProviderDestroy(provider);
    umfOsMemoryProviderParamsDestroy(provider_params);
}

TEST(scalablePoolTest, default_name_null_handle) {
    const char *name = nullptr;
    EXPECT_EQ(umfScalablePoolOps()->get_name(nullptr, &name),
              UMF_RESULT_SUCCESS);
    EXPECT_STREQ(name, "scalable");
}
