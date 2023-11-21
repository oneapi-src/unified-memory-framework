// Copyright (C) 2023 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "memoryPool.hpp"
#include "pool.hpp"
#include "provider.hpp"
#include "provider_null.h"
#include "provider_trace.h"
#include "umf/pools/pool_disjoint.h"

umf_disjoint_pool_params poolConfig() {
    umf_disjoint_pool_params config{};
    config.SlabMinSize = 4096;
    config.MaxPoolableSize = 4096;
    config.Capacity = 4;
    config.MinBucketSize = 64;
    return config;
}

static auto makePool() {
    auto [ret, provider] =
        umf::memoryProviderMakeUnique<umf_test::provider_malloc>();
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    umf_memory_provider_handle_t provider_handle;
    provider_handle = provider.release();

    // capture provider and destroy it after the pool is destroyed
    auto poolDestructor = [provider_handle](umf_memory_pool_handle_t pool) {
        umfPoolDestroy(pool);
        umfMemoryProviderDestroy(provider_handle);
    };

    umf_memory_pool_handle_t pool = NULL;
    struct umf_disjoint_pool_params params = poolConfig();
    enum umf_result_t retp =
        umfPoolCreate(&UMF_DISJOINT_POOL_OPS, provider_handle, &params, &pool);
    EXPECT_EQ(retp, UMF_RESULT_SUCCESS);

    return umf::pool_unique_handle_t(pool, std::move(poolDestructor));
}

using umf_test::test;

TEST_F(test, freeErrorPropagation) {
    static enum umf_result_t freeReturn = UMF_RESULT_SUCCESS;
    struct memory_provider : public umf_test::provider_base {
        enum umf_result_t alloc(size_t size, size_t, void **ptr) noexcept {
            *ptr = malloc(size);
            return UMF_RESULT_SUCCESS;
        }
        enum umf_result_t free(void *ptr,
                               [[maybe_unused]] size_t size) noexcept {
            if (freeReturn == UMF_RESULT_SUCCESS) {
                ::free(ptr);
            }
            return freeReturn;
        }
    };

    auto [ret, providerUnique] =
        umf::memoryProviderMakeUnique<memory_provider>();
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    umf_memory_provider_handle_t provider_handle;
    provider_handle = providerUnique.get();

    // force all allocations to go to memory provider
    struct umf_disjoint_pool_params params = poolConfig();
    params.MaxPoolableSize = 0;

    umf_memory_pool_handle_t pool = NULL;
    enum umf_result_t retp =
        umfPoolCreate(&UMF_DISJOINT_POOL_OPS, provider_handle, &params, &pool);
    EXPECT_EQ(retp, UMF_RESULT_SUCCESS);
    auto poolHandle = umf_test::wrapPoolUnique(pool);

    static constexpr size_t size = 1024;
    void *ptr = umfPoolMalloc(pool, size);

    freeReturn = UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    auto freeRet = umfPoolFree(pool, ptr);

    EXPECT_EQ(freeRet, freeReturn);
}

TEST_F(test, sharedLimits) {
#if !UMF_ENABLE_POOL_TRACKING_TESTS
    GTEST_SKIP() << "Pool Tracking needs to be enabled";
#endif

    static size_t numAllocs = 0;
    static size_t numFrees = 0;

    struct memory_provider : public umf_test::provider_base {
        enum umf_result_t alloc(size_t size, size_t, void **ptr) noexcept {
            *ptr = malloc(size);
            numAllocs++;
            return UMF_RESULT_SUCCESS;
        }
        enum umf_result_t free(void *ptr,
                               [[maybe_unused]] size_t size) noexcept {
            ::free(ptr);
            numFrees++;
            return UMF_RESULT_SUCCESS;
        }
    };

    static constexpr size_t SlabMinSize = 1024;
    static constexpr size_t MaxSize = 4 * SlabMinSize;

    auto config = poolConfig();
    config.SlabMinSize = SlabMinSize;

    auto limits =
        std::unique_ptr<umf_disjoint_pool_shared_limits,
                        decltype(&umfDisjointPoolSharedLimitsDestroy)>(
            umfDisjointPoolSharedLimitsCreate(MaxSize),
            &umfDisjointPoolSharedLimitsDestroy);

    config.SharedLimits = limits.get();

    auto [ret, provider] = umf::memoryProviderMakeUnique<memory_provider>();
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    umf_memory_pool_handle_t pool1 = NULL;
    umf_memory_pool_handle_t pool2 = NULL;
    ret = umfPoolCreate(&UMF_DISJOINT_POOL_OPS, provider.get(), (void *)&config,
                        &pool1);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    auto poolHandle1 = umf_test::wrapPoolUnique(pool1);

    ret = umfPoolCreate(&UMF_DISJOINT_POOL_OPS, provider.get(), (void *)&config,
                        &pool2);
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

INSTANTIATE_TEST_SUITE_P(disjointPoolTests, umfPoolTest,
                         ::testing::Values(makePool));

INSTANTIATE_TEST_SUITE_P(disjointPoolTests, umfMemTest,
                         ::testing::Values(std::make_tuple(
                             [] {
                                 return umf_test::makePoolWithOOMProvider(
                                     static_cast<int>(poolConfig().Capacity),
                                     &UMF_DISJOINT_POOL_OPS, poolConfig());
                             },
                             static_cast<int>(poolConfig().Capacity) / 2)));

GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfMultiPoolTest);
INSTANTIATE_TEST_SUITE_P(disjointMultiPoolTests, umfMultiPoolTest,
                         ::testing::Values(makePool));
