// Copyright (C) 2023 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "umf/pools/pool_jemalloc.h"
#include "umf/providers/provider_os_memory.h"

#include "pool.hpp"
#include "poolFixtures.hpp"

using umf_test::test;
using namespace umf_test;

using os_params_unique_handle_t =
    std::unique_ptr<umf_os_memory_provider_params_t,
                    decltype(&umfOsMemoryProviderParamsDestroy)>;

os_params_unique_handle_t createOsMemoryProviderParams() {
    umf_os_memory_provider_params_handle_t params = nullptr;
    umf_result_t res = umfOsMemoryProviderParamsCreate(&params);
    if (res != UMF_RESULT_SUCCESS) {
        throw std::runtime_error("Failed to create os memory provider params");
    }

    return os_params_unique_handle_t(params, &umfOsMemoryProviderParamsDestroy);
}
auto defaultParams = createOsMemoryProviderParams();

INSTANTIATE_TEST_SUITE_P(jemallocPoolTest, umfPoolTest,
                         ::testing::Values(poolCreateExtParams{
                             umfJemallocPoolOps(), nullptr,
                             umfOsMemoryProviderOps(), defaultParams.get(),
                             nullptr}));

// this test makes sure that jemalloc does not use
// memory provider to allocate metadata (and hence
// is suitable for cases where memory is not accessible
// on the host)
TEST_F(test, metadataNotAllocatedUsingProvider) {
    static constexpr size_t allocSize = 1024;
    static constexpr size_t numAllocs = 1024;

    // set coarse grain allocations to PROT_NONE so that we can be sure
    // jemalloc does not touch any of the allocated memory
    umf_os_memory_provider_params_handle_t params = nullptr;
    umf_result_t res = umfOsMemoryProviderParamsCreate(&params);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    res = umfOsMemoryProviderParamsSetProtection(params, UMF_PROTECTION_NONE);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);

    auto pool =
        poolCreateExtUnique({umfJemallocPoolOps(), nullptr,
                             umfOsMemoryProviderOps(), params, nullptr});

    res = umfOsMemoryProviderParamsDestroy(params);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);

    std::vector<std::shared_ptr<void>> allocs;
    for (size_t i = 0; i < numAllocs; i++) {
        allocs.emplace_back(
            umfPoolMalloc(pool.get(), allocSize),
            [pool = pool.get()](void *ptr) { umfPoolFree(pool, ptr); });
    }
}

using jemallocPoolParams = bool;
struct umfJemallocPoolParamsTest
    : umf_test::test,
      ::testing::WithParamInterface<jemallocPoolParams> {

    struct validation_params_t {
        bool keep_all_memory;
    };

    struct provider_validator : public umf_test::provider_ba_global {
        using base_provider = umf_test::provider_ba_global;

        umf_result_t initialize(validation_params_t *params) {
            EXPECT_NE(params, nullptr);
            expected_params = params;
            return UMF_RESULT_SUCCESS;
        }
        umf_result_t free(void *ptr, size_t size) {
            EXPECT_EQ(expected_params->keep_all_memory, false);
            return base_provider::free(ptr, size);
        }

        validation_params_t *expected_params;
    };

    static constexpr umf_memory_provider_ops_t VALIDATOR_PROVIDER_OPS =
        umf::providerMakeCOps<provider_validator, validation_params_t>();

    umfJemallocPoolParamsTest() : expected_params{false}, params(nullptr) {}
    void SetUp() override {
        test::SetUp();
        expected_params.keep_all_memory = this->GetParam();
        umf_result_t ret = umfJemallocPoolParamsCreate(&params);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        ret = umfJemallocPoolParamsSetKeepAllMemory(
            params, expected_params.keep_all_memory);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    }

    void TearDown() override {
        umfJemallocPoolParamsDestroy(params);
        test::TearDown();
    }

    umf::pool_unique_handle_t makePool() {
        umf_memory_provider_handle_t hProvider = nullptr;
        umf_memory_pool_handle_t hPool = nullptr;

        auto ret = umfMemoryProviderCreate(&VALIDATOR_PROVIDER_OPS,
                                           &expected_params, &hProvider);
        EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

        ret = umfPoolCreate(umfJemallocPoolOps(), hProvider, params,
                            UMF_POOL_CREATE_FLAG_OWN_PROVIDER, &hPool);
        EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

        return umf::pool_unique_handle_t(hPool, &umfPoolDestroy);
    }

    void allocFreeFlow() {
        static const size_t ALLOC_SIZE = 128;
        static const size_t NUM_ALLOCATIONS = 100;
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
    umf_jemalloc_pool_params_handle_t params;
};

TEST_P(umfJemallocPoolParamsTest, allocFree) { allocFreeFlow(); }

TEST_P(umfJemallocPoolParamsTest, updateParams) {
    expected_params.keep_all_memory = !expected_params.keep_all_memory;
    umf_result_t ret = umfJemallocPoolParamsSetKeepAllMemory(
        params, expected_params.keep_all_memory);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    allocFreeFlow();
}

TEST_P(umfJemallocPoolParamsTest, invalidParams) {
    umf_result_t ret = umfJemallocPoolParamsCreate(nullptr);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = umfJemallocPoolParamsSetKeepAllMemory(nullptr, true);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = umfJemallocPoolParamsSetKeepAllMemory(nullptr, false);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = umfJemallocPoolParamsDestroy(nullptr);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfJemallocPoolParamsTest);

/* TODO: enable this test after the issue #903 is fixed.
(https://github.com/oneapi-src/unified-memory-framework/issues/903)
INSTANTIATE_TEST_SUITE_P(jemallocPoolTest, umfJemallocPoolParamsTest,
                         testing::Values(false, true));
*/
