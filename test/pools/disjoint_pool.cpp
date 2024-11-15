// Copyright (C) 2023-2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <memory>

#include "pool.hpp"
#include "poolFixtures.hpp"
#include "pool_disjoint.h"
#include "provider.hpp"
#include "provider_null.h"
#include "provider_trace.h"

using disjoint_params_unique_handle_t =
    std::unique_ptr<umf_disjoint_pool_params_t,
                    decltype(&umfDisjointPoolParamsDestroy)>;

static constexpr size_t DEFAULT_DISJOINT_SLAB_MIN_SIZE = 4096;
static constexpr size_t DEFAULT_DISJOINT_MAX_POOLABLE_SIZE = 4096;
static constexpr size_t DEFAULT_DISJOINT_CAPACITY = 4;
static constexpr size_t DEFAULT_DISJOINT_MIN_BUCKET_SIZE = 64;

disjoint_params_unique_handle_t poolConfig() {
    umf_disjoint_pool_params_handle_t config = nullptr;
    umf_result_t res = umfDisjointPoolParamsCreate(&config);
    if (res != UMF_RESULT_SUCCESS) {
        throw std::runtime_error("Failed to create pool params");
    }
    res = umfDisjointPoolParamsSetSlabMinSize(config,
                                              DEFAULT_DISJOINT_SLAB_MIN_SIZE);
    if (res != UMF_RESULT_SUCCESS) {
        throw std::runtime_error("Failed to set slab min size");
    }
    res = umfDisjointPoolParamsSetMaxPoolableSize(
        config, DEFAULT_DISJOINT_MAX_POOLABLE_SIZE);
    if (res != UMF_RESULT_SUCCESS) {
        throw std::runtime_error("Failed to set max poolable size");
    }
    res = umfDisjointPoolParamsSetCapacity(config, DEFAULT_DISJOINT_CAPACITY);
    if (res != UMF_RESULT_SUCCESS) {
        throw std::runtime_error("Failed to set capacity");
    }
    res = umfDisjointPoolParamsSetMinBucketSize(
        config, DEFAULT_DISJOINT_MIN_BUCKET_SIZE);
    if (res != UMF_RESULT_SUCCESS) {
        throw std::runtime_error("Failed to set min bucket size");
    }

    return disjoint_params_unique_handle_t(config,
                                           &umfDisjointPoolParamsDestroy);
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
    disjoint_params_unique_handle_t params = poolConfig();
    umf_result_t retp =
        umfDisjointPoolParamsSetMaxPoolableSize(params.get(), 0);
    EXPECT_EQ(retp, UMF_RESULT_SUCCESS);

    umf_memory_pool_handle_t pool = NULL;
    retp = umfPoolCreate(umfDisjointPoolOps(), provider_handle, params.get(), 0,
                         &pool);
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

    disjoint_params_unique_handle_t config = poolConfig();
    umf_result_t ret =
        umfDisjointPoolParamsSetSlabMinSize(config.get(), SlabMinSize);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    auto limits =
        std::unique_ptr<umf_disjoint_pool_shared_limits_t,
                        decltype(&umfDisjointPoolSharedLimitsDestroy)>(
            umfDisjointPoolSharedLimitsCreate(MaxSize),
            &umfDisjointPoolSharedLimitsDestroy);

    ret = umfDisjointPoolParamsSetSharedLimits(config.get(), limits.get());
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    auto provider =
        wrapProviderUnique(createProviderChecked(&provider_ops, nullptr));

    umf_memory_pool_handle_t pool1 = NULL;
    umf_memory_pool_handle_t pool2 = NULL;
    ret = umfPoolCreate(umfDisjointPoolOps(), provider.get(),
                        (void *)config.get(), 0, &pool1);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    auto poolHandle1 = umf_test::wrapPoolUnique(pool1);

    ret = umfPoolCreate(umfDisjointPoolOps(), provider.get(),
                        (void *)config.get(), 0, &pool2);
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

TEST_F(test, disjointPoolNullParams) {
    umf_result_t res = umfDisjointPoolParamsCreate(nullptr);
    EXPECT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umf_disjoint_pool_params_handle_t params = nullptr;
    res = umfDisjointPoolParamsSetSlabMinSize(params, 4096);
    EXPECT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfDisjointPoolParamsSetMaxPoolableSize(params, 4096);
    EXPECT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfDisjointPoolParamsSetCapacity(params, 4);
    EXPECT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfDisjointPoolParamsSetMinBucketSize(params, 64);
    EXPECT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfDisjointPoolParamsSetTrace(params, 0);
    EXPECT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfDisjointPoolParamsSetSharedLimits(params, nullptr);
    EXPECT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfDisjointPoolParamsSetName(params, "test_disjoint_pool");
}

TEST_F(test, disjointPoolInvalidBucketSize) {
    umf_disjoint_pool_params_handle_t params = nullptr;
    umf_result_t res = umfDisjointPoolParamsCreate(&params);
    EXPECT_EQ(res, UMF_RESULT_SUCCESS);

    res = umfDisjointPoolParamsSetMinBucketSize(params, 0);
    EXPECT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfDisjointPoolParamsSetMinBucketSize(params, 1);
    EXPECT_EQ(res, UMF_RESULT_SUCCESS);

    res = umfDisjointPoolParamsSetMinBucketSize(params, 2);
    EXPECT_EQ(res, UMF_RESULT_SUCCESS);

    res = umfDisjointPoolParamsSetMinBucketSize(params, 3);
    EXPECT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfDisjointPoolParamsSetMinBucketSize(params, 4);
    EXPECT_EQ(res, UMF_RESULT_SUCCESS);

    res = umfDisjointPoolParamsSetMinBucketSize(params, 6);
    EXPECT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfDisjointPoolParamsSetMinBucketSize(params, 8);
    EXPECT_EQ(res, UMF_RESULT_SUCCESS);

    res = umfDisjointPoolParamsSetMinBucketSize(params, 24);
    EXPECT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umfDisjointPoolParamsDestroy(params);
}

disjoint_params_unique_handle_t defaultPoolConfig = poolConfig();
INSTANTIATE_TEST_SUITE_P(disjointPoolTests, umfPoolTest,
                         ::testing::Values(poolCreateExtParams{
                             umfDisjointPoolOps(),
                             (void *)defaultPoolConfig.get(),
                             &BA_GLOBAL_PROVIDER_OPS, nullptr, nullptr}));

INSTANTIATE_TEST_SUITE_P(disjointPoolTests, umfMemTest,
                         ::testing::Values(std::make_tuple(
                             poolCreateExtParams{
                                 umfDisjointPoolOps(),
                                 (void *)defaultPoolConfig.get(),
                                 &MOCK_OUT_OF_MEM_PROVIDER_OPS,
                                 (void *)&DEFAULT_DISJOINT_CAPACITY, nullptr},
                             static_cast<int>(DEFAULT_DISJOINT_CAPACITY) / 2)));

INSTANTIATE_TEST_SUITE_P(disjointMultiPoolTests, umfMultiPoolTest,
                         ::testing::Values(poolCreateExtParams{
                             umfDisjointPoolOps(),
                             (void *)defaultPoolConfig.get(),
                             &BA_GLOBAL_PROVIDER_OPS, nullptr, nullptr}));
