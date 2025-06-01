// Copyright (C) 2023-2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <memory>

#include <umf/base.h>
#include <umf/memory_pool.h>
#include <umf/pools/pool_disjoint.h>

#include "pool.hpp"
#include "pool/pool_disjoint_internal.h"
#include "poolFixtures.hpp"
#include "provider.hpp"
#include "provider_null.h"
#include "provider_trace.h"

using umf_test::test;
using namespace umf_test;

TEST_F(test, internals) {
    static umf_result_t expectedResult = UMF_RESULT_SUCCESS;
    struct memory_provider : public umf_test::provider_base_t {
        umf_result_t alloc(size_t size, size_t alignment, void **ptr) noexcept {
            *ptr = umf_ba_global_aligned_alloc(size, alignment);
            return UMF_RESULT_SUCCESS;
        }

        umf_result_t free(void *ptr, [[maybe_unused]] size_t size) noexcept {
            // do the actual free only when we expect the success
            if (expectedResult == UMF_RESULT_SUCCESS) {
                umf_ba_global_free(ptr);
            }
            return expectedResult;
        }

        umf_result_t
        get_min_page_size([[maybe_unused]] const void *ptr,
                          [[maybe_unused]] size_t *pageSize) noexcept {
            *pageSize = 1024;
            return UMF_RESULT_SUCCESS;
        }
    };
    umf_memory_provider_ops_t provider_ops =
        umf_test::providerMakeCOps<memory_provider, void>();

    auto providerUnique =
        wrapProviderUnique(createProviderChecked(&provider_ops, nullptr));

    umf_memory_provider_handle_t provider_handle;
    provider_handle = providerUnique.get();

    umf_disjoint_pool_params_handle_t params =
        (umf_disjoint_pool_params_handle_t)defaultDisjointPoolConfig();
    // set to maximum tracing
    params->pool_trace = 3;
    params->max_poolable_size = 1024 * 1024;

    // in "internals" test we use ops interface to directly manipulate the pool
    // structure
    const umf_memory_pool_ops_t *ops = umfDisjointPoolOps();
    EXPECT_NE(ops, nullptr);

    disjoint_pool_t *pool;
    umf_result_t res = ops->initialize(provider_handle, params, (void **)&pool);
    EXPECT_EQ(res, UMF_RESULT_SUCCESS);
    EXPECT_NE(pool, nullptr);
    EXPECT_EQ(pool->provider_min_page_size, (size_t)1024);

    // check buckets sizes
    size_t expected_size = DEFAULT_DISJOINT_MIN_BUCKET_SIZE;
    EXPECT_EQ(pool->buckets[0]->size, expected_size);
    EXPECT_EQ(pool->buckets[pool->buckets_num - 1]->size,
              (size_t)1 << 31); // 2GB
    for (size_t i = 0; i < pool->buckets_num; i++) {
        bucket_t *bucket = pool->buckets[i];
        EXPECT_NE(bucket, nullptr);
        EXPECT_EQ(bucket->size, expected_size);

        // assuming DEFAULT_DISJOINT_MIN_BUCKET_SIZE = 64, expected bucket
        // sizes are: 64, 96, 128, 192, 256, ..., 2GB
        if (i % 2 == 0) {
            expected_size += expected_size / 2;
        } else {
            expected_size = DEFAULT_DISJOINT_MIN_BUCKET_SIZE << ((i + 1) / 2);
        }
    }

    // test small allocations
    size_t size = 8;
    void *ptr = ops->malloc(pool, size);
    EXPECT_NE(ptr, nullptr);

    // get bucket - because of small size this should be the first bucket in
    // the pool
    bucket_t *bucket = pool->buckets[0];
    EXPECT_NE(bucket, nullptr);

    // check bucket stats
    EXPECT_EQ(bucket->alloc_count, (size_t)1);

    // first allocation will always use external memory (newly added to the
    // pool) and this is counted as allocation from the outside of the pool
    EXPECT_EQ(bucket->alloc_pool_count, (size_t)0);
    EXPECT_EQ(bucket->curr_slabs_in_use, (size_t)1);

    // check slab - there should be only single slab allocated
    EXPECT_NE(bucket->available_slabs, nullptr);
    EXPECT_EQ(bucket->available_slabs_num, (size_t)1);
    EXPECT_EQ(bucket->available_slabs->next, nullptr);
    slab_t *slab = bucket->available_slabs->val;

    // check slab stats
    EXPECT_GE(slab->slab_size, params->slab_min_size);
    EXPECT_GE(slab->num_chunks_total, slab->slab_size / bucket->size);

    // check allocation in slab
    EXPECT_EQ(slab_read_chunk_bit(slab, 0), false);
    EXPECT_EQ(slab_read_chunk_bit(slab, 1), true);

    // TODO:
    // * multiple alloc + free from single bucket
    // * alignments
    // * full slab alloc
    // * slab overflow
    // * chunked slabs
    // * multiple alloc + free from different buckets
    // * alloc something outside pool (> MaxPoolableSize)
    // * test capacity
    // * check minBucketSize
    // * test large objects
    // * check available_slabs_num

    // cleanup
    ops->finalize(pool);
    umfDisjointPoolParamsDestroy(params);
}

TEST_F(test, freeErrorPropagation) {
    static umf_result_t expectedResult = UMF_RESULT_SUCCESS;
    struct memory_provider : public umf_test::provider_base_t {
        umf_result_t alloc(size_t size, size_t alignment, void **ptr) noexcept {
            *ptr = umf_ba_global_aligned_alloc(size, alignment);
            return UMF_RESULT_SUCCESS;
        }

        umf_result_t free(void *ptr, [[maybe_unused]] size_t size) noexcept {
            // do the actual free only when we expect the success
            if (expectedResult == UMF_RESULT_SUCCESS) {
                umf_ba_global_free(ptr);
            }
            return expectedResult;
        }
    };
    umf_memory_provider_ops_t provider_ops =
        umf_test::providerMakeCOps<memory_provider, void>();

    auto providerUnique =
        wrapProviderUnique(createProviderChecked(&provider_ops, nullptr));

    umf_memory_provider_handle_t provider_handle;
    provider_handle = providerUnique.get();

    // force all allocations to go to memory provider
    umf_disjoint_pool_params_handle_t params;
    umf_result_t retp = umfDisjointPoolParamsCreate(&params);
    EXPECT_EQ(retp, UMF_RESULT_SUCCESS);
    retp = umfDisjointPoolParamsSetMaxPoolableSize(params, 0);
    EXPECT_EQ(retp, UMF_RESULT_SUCCESS);

    umf_memory_pool_handle_t pool = NULL;
    retp =
        umfPoolCreate(umfDisjointPoolOps(), provider_handle, params, 0, &pool);
    EXPECT_EQ(retp, UMF_RESULT_SUCCESS);
    auto poolHandle = umf_test::wrapPoolUnique(pool);

    retp = umfDisjointPoolParamsDestroy(params);
    EXPECT_EQ(retp, UMF_RESULT_SUCCESS);

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
        umf_result_t alloc(size_t size, size_t alignment, void **ptr) noexcept {
            *ptr = umf_ba_global_aligned_alloc(size, alignment);
            numAllocs++;
            return UMF_RESULT_SUCCESS;
        }
        umf_result_t free(void *ptr, [[maybe_unused]] size_t size) noexcept {
            umf_ba_global_free(ptr);
            numFrees++;
            return UMF_RESULT_SUCCESS;
        }
    };
    umf_memory_provider_ops_t provider_ops =
        umf_test::providerMakeCOps<memory_provider, void>();

    static constexpr size_t SlabMinSize = 1024;
    static constexpr size_t MaxSize = 4 * SlabMinSize;

    umf_disjoint_pool_params_handle_t params =
        (umf_disjoint_pool_params_handle_t)defaultDisjointPoolConfig();
    umf_result_t ret = umfDisjointPoolParamsSetSlabMinSize(params, SlabMinSize);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    auto limits =
        std::unique_ptr<umf_disjoint_pool_shared_limits_t,
                        decltype(&umfDisjointPoolSharedLimitsDestroy)>(
            umfDisjointPoolSharedLimitsCreate(MaxSize),
            &umfDisjointPoolSharedLimitsDestroy);

    ret = umfDisjointPoolParamsSetSharedLimits(params, limits.get());
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    auto provider =
        wrapProviderUnique(createProviderChecked(&provider_ops, nullptr));

    umf_memory_pool_handle_t pool1 = NULL;
    umf_memory_pool_handle_t pool2 = NULL;
    ret =
        umfPoolCreate(umfDisjointPoolOps(), provider.get(), params, 0, &pool1);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    auto poolHandle1 = umf_test::wrapPoolUnique(pool1);

    ret =
        umfPoolCreate(umfDisjointPoolOps(), provider.get(), params, 0, &pool2);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    auto poolHandle2 = umf_test::wrapPoolUnique(pool2);

    ret = umfDisjointPoolParamsDestroy(params);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    EXPECT_EQ((size_t)0, numAllocs);
    EXPECT_EQ((size_t)0, numFrees);

    std::vector<std::unique_ptr<void, decltype(&umfFree)>> ptrs;
    for (size_t i = 0; i < MaxSize / SlabMinSize; i++) {
        ptrs.emplace_back(umfPoolMalloc(pool1, SlabMinSize), &umfFree);
        ptrs.emplace_back(umfPoolMalloc(pool2, SlabMinSize), &umfFree);
    }

    EXPECT_EQ(MaxSize / SlabMinSize * 2, numAllocs);
    EXPECT_EQ((size_t)0, numFrees);

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

TEST_F(test, disjointPoolTrim) {
    struct memory_provider : public umf_test::provider_base_t {
        umf_result_t alloc(size_t size, size_t alignment, void **ptr) noexcept {
            *ptr = umf_ba_global_aligned_alloc(size, alignment);
            return UMF_RESULT_SUCCESS;
        }

        umf_result_t free(void *ptr, [[maybe_unused]] size_t size) noexcept {
            umf_ba_global_free(ptr);
            return UMF_RESULT_SUCCESS;
        }
    };

    umf_memory_provider_ops_t provider_ops =
        umf_test::providerMakeCOps<memory_provider, void>();

    auto providerUnique =
        wrapProviderUnique(createProviderChecked(&provider_ops, nullptr));

    umf_memory_provider_handle_t provider_handle;
    provider_handle = providerUnique.get();

    umf_disjoint_pool_params_handle_t params =
        (umf_disjoint_pool_params_handle_t)defaultDisjointPoolConfig();
    params->pool_trace = 3;
    // Set the slab min size to 64 so allocating 64 bytes will use the whole
    // slab.
    params->slab_min_size = 64;
    params->capacity = 4;

    // in "internals" test we use ops interface to directly manipulate the pool
    // structure
    const umf_memory_pool_ops_t *ops = umfDisjointPoolOps();
    EXPECT_NE(ops, nullptr);

    disjoint_pool_t *pool;
    umf_result_t res = ops->initialize(provider_handle, params, (void **)&pool);
    EXPECT_EQ(res, UMF_RESULT_SUCCESS);
    EXPECT_NE(pool, nullptr);

    // do 4 allocs, then free all of them
    size_t size = 64;
    void *ptrs[4] = {0};
    ptrs[0] = ops->malloc(pool, size);
    EXPECT_NE(ptrs[0], nullptr);
    ptrs[1] = ops->malloc(pool, size);
    EXPECT_NE(ptrs[1], nullptr);
    ptrs[2] = ops->malloc(pool, size);
    EXPECT_NE(ptrs[2], nullptr);
    ptrs[3] = ops->malloc(pool, size);
    EXPECT_NE(ptrs[3], nullptr);

    ops->free(pool, ptrs[0]);
    ops->free(pool, ptrs[1]);
    ops->free(pool, ptrs[2]);
    ops->free(pool, ptrs[3]);

    // Because we set the slab min size to 64, each allocation should go to the
    // separate slab. Additionally, because we set the capacity to 4, all slabs
    // should still be in the pool available for new allocations.
    EXPECT_EQ(pool->buckets[0]->available_slabs_num, 4);
    EXPECT_EQ(pool->buckets[0]->curr_slabs_in_use, 0);
    EXPECT_EQ(pool->buckets[0]->curr_slabs_in_pool, 4);

    // Trim memory - leave only one slab
    umfDisjointPoolTrimMemory(pool, 1);
    EXPECT_EQ(pool->buckets[0]->available_slabs_num, 1);
    EXPECT_EQ(pool->buckets[0]->curr_slabs_in_pool, 1);

    // Trim the rest of memory
    umfDisjointPoolTrimMemory(pool, 0);
    EXPECT_EQ(pool->buckets[0]->available_slabs_num, 0);
    EXPECT_EQ(pool->buckets[0]->curr_slabs_in_pool, 0);

    ops->finalize(pool);
    res = umfDisjointPoolParamsDestroy(params);
    EXPECT_EQ(res, UMF_RESULT_SUCCESS);
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

TEST_F(test, disjointPoolName) {
    umf_disjoint_pool_params_handle_t params = nullptr;
    umf_result_t res = umfDisjointPoolParamsCreate(&params);
    EXPECT_EQ(res, UMF_RESULT_SUCCESS);
    umf_memory_provider_handle_t provider_handle = nullptr;
    umf_memory_pool_handle_t pool = NULL;

    struct memory_provider : public umf_test::provider_base_t {};

    umf_memory_provider_ops_t provider_ops =
        umf_test::providerMakeCOps<memory_provider, void>();

    auto providerUnique =
        wrapProviderUnique(createProviderChecked(&provider_ops, nullptr));

    provider_handle = providerUnique.get();

    res =
        umfPoolCreate(umfDisjointPoolOps(), provider_handle, params, 0, &pool);
    EXPECT_EQ(res, UMF_RESULT_SUCCESS);
    const char *name = umfPoolGetName(pool);
    EXPECT_STREQ(name, "disjoint");

    umfPoolDestroy(pool);
    umfDisjointPoolParamsDestroy(params);
}

INSTANTIATE_TEST_SUITE_P(disjointPoolTests, umfPoolTest,
                         ::testing::Values(poolCreateExtParams{
                             umfDisjointPoolOps(), defaultDisjointPoolConfig,
                             defaultDisjointPoolConfigDestroy,
                             &BA_GLOBAL_PROVIDER_OPS, nullptr, nullptr}));

void *memProviderParams() { return (void *)&DEFAULT_DISJOINT_CAPACITY; }

INSTANTIATE_TEST_SUITE_P(
    disjointPoolTests, umfMemTest,
    ::testing::Values(std::make_tuple(
        poolCreateExtParams{umfDisjointPoolOps(), defaultDisjointPoolConfig,
                            defaultDisjointPoolConfigDestroy,
                            &MOCK_OUT_OF_MEM_PROVIDER_OPS, memProviderParams,
                            nullptr},
        static_cast<int>(DEFAULT_DISJOINT_CAPACITY) / 2)));

INSTANTIATE_TEST_SUITE_P(disjointMultiPoolTests, umfMultiPoolTest,
                         ::testing::Values(poolCreateExtParams{
                             umfDisjointPoolOps(), defaultDisjointPoolConfig,
                             defaultDisjointPoolConfigDestroy,
                             &BA_GLOBAL_PROVIDER_OPS, nullptr, nullptr}));
