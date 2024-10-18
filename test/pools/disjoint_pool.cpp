// Copyright (C) 2023-2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "pool.hpp"
#include "poolFixtures.hpp"
#include "pool_disjoint.h"
#include "provider.hpp"
#include "provider_null.h"
#include "provider_trace.h"

umf_disjoint_pool_params_t poolConfig() {
    umf_disjoint_pool_params_t config{};
    config.SlabMinSize = 4096;
    config.MaxPoolableSize = 4096;
    config.Capacity = 4;
    config.MinBucketSize = 64;
    return config;
}

using umf_test::test;
using namespace umf_test;

TEST_F(test, freeErrorPropagation) {
    static umf_result_t expectedResult = UMF_RESULT_SUCCESS;
    struct memory_provider : public umf_test::provider_base_t {
        umf_result_t alloc(size_t size, size_t, void **ptr) noexcept {
            *ptr = malloc(size);
            return UMF_RESULT_SUCCESS;
        }

        umf_result_t free(void *ptr, [[maybe_unused]] size_t size) noexcept {
            // do the actual free only when we expect the success
            if (expectedResult == UMF_RESULT_SUCCESS) {
                ::free(ptr);
            }
            return expectedResult;
        }
    };
    umf_memory_provider_ops_t provider_ops =
        umf::providerMakeCOps<memory_provider, void>();

    auto providerUnique =
        wrapProviderUnique(createProviderChecked(&provider_ops, nullptr));

    umf_memory_provider_handle_t provider_handle;
    provider_handle = providerUnique.get();

    // force all allocations to go to memory provider
    umf_disjoint_pool_params_t params = poolConfig();
    params.MaxPoolableSize = 0;

    umf_memory_pool_handle_t pool = NULL;
    umf_result_t retp =
        umfPoolCreate(umfDisjointPoolOps(), provider_handle, &params, 0, &pool);
    EXPECT_EQ(retp, UMF_RESULT_SUCCESS);
    auto poolHandle = umf_test::wrapPoolUnique(pool);

    static constexpr size_t size = 1024;
    void *ptr = umfPoolMalloc(pool, size);

    // this umfPoolFree() will not free the memory
    expectedResult = UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    umf_result_t testResult = umfPoolFree(pool, ptr);
    EXPECT_EQ(testResult, expectedResult);
    expectedResult = UMF_RESULT_SUCCESS;

    // free the memory to avoid memory leak
    testResult = umfPoolFree(pool, ptr);
    EXPECT_EQ(testResult, expectedResult);
}

TEST_F(test, sharedLimits) {
    static size_t numAllocs = 0;
    static size_t numFrees = 0;

    struct memory_provider : public umf_test::provider_base_t {
        umf_result_t alloc(size_t size, size_t, void **ptr) noexcept {
            *ptr = malloc(size);
            numAllocs++;
            return UMF_RESULT_SUCCESS;
        }
        umf_result_t free(void *ptr, [[maybe_unused]] size_t size) noexcept {
            ::free(ptr);
            numFrees++;
            return UMF_RESULT_SUCCESS;
        }
    };
    umf_memory_provider_ops_t provider_ops =
        umf::providerMakeCOps<memory_provider, void>();

    static constexpr size_t SlabMinSize = 1024;
    static constexpr size_t MaxSize = 4 * SlabMinSize;

    auto config = poolConfig();
    config.SlabMinSize = SlabMinSize;

    auto limits =
        std::unique_ptr<umf_disjoint_pool_shared_limits_t,
                        decltype(&umfDisjointPoolSharedLimitsDestroy)>(
            umfDisjointPoolSharedLimitsCreate(MaxSize),
            &umfDisjointPoolSharedLimitsDestroy);

    config.SharedLimits = limits.get();

    auto provider =
        wrapProviderUnique(createProviderChecked(&provider_ops, nullptr));

    umf_memory_pool_handle_t pool1 = NULL;
    umf_memory_pool_handle_t pool2 = NULL;
    auto ret = umfPoolCreate(umfDisjointPoolOps(), provider.get(),
                             (void *)&config, 0, &pool1);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    auto poolHandle1 = umf_test::wrapPoolUnique(pool1);

    ret = umfPoolCreate(umfDisjointPoolOps(), provider.get(), (void *)&config,
                        0, &pool2);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    auto poolHandle2 = umf_test::wrapPoolUnique(pool2);

    EXPECT_EQ(0, numAllocs);
    EXPECT_EQ(0, numFrees);

    std::vector<std::unique_ptr<void, decltype(&umfFree)>> ptrs;
    for (size_t i = 0; i < MaxSize / SlabMinSize; i++) {
        ptrs.emplace_back(umfPoolMalloc(pool1, SlabMinSize), &umfFree);
        ptrs.emplace_back(umfPoolMalloc(pool2, SlabMinSize), &umfFree);
    }

    EXPECT_EQ(MaxSize / SlabMinSize * 2, numAllocs);
    EXPECT_EQ(0, numFrees);

    ptrs.clear();

    // There should still be MaxSize memory in the pool (MaxSize/SlabMinSize allocations)
    EXPECT_EQ(MaxSize / SlabMinSize * 2, numAllocs);
    EXPECT_EQ(MaxSize / SlabMinSize, numFrees);

    poolHandle1.reset();
    poolHandle2.reset();

    // All memory should be freed now
    EXPECT_EQ(MaxSize / SlabMinSize * 2, numAllocs);
    EXPECT_EQ(MaxSize / SlabMinSize * 2, numFrees);
}

auto defaultPoolConfig = poolConfig();
INSTANTIATE_TEST_SUITE_P(disjointPoolTests, umfPoolTest,
                         ::testing::Values(poolCreateExtParams{
                             umfDisjointPoolOps(), (void *)&defaultPoolConfig,
                             &MALLOC_PROVIDER_OPS, nullptr, nullptr}));

INSTANTIATE_TEST_SUITE_P(
    disjointPoolTests, umfMemTest,
    ::testing::Values(std::make_tuple(
        poolCreateExtParams{umfDisjointPoolOps(), (void *)&defaultPoolConfig,
                            &MOCK_OUT_OF_MEM_PROVIDER_OPS,
                            (void *)&defaultPoolConfig.Capacity, nullptr},
        static_cast<int>(defaultPoolConfig.Capacity) / 2)));

INSTANTIATE_TEST_SUITE_P(disjointMultiPoolTests, umfMultiPoolTest,
                         ::testing::Values(poolCreateExtParams{
                             umfDisjointPoolOps(), (void *)&defaultPoolConfig,
                             &MALLOC_PROVIDER_OPS, nullptr, nullptr}));
