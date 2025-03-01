// Copyright (C) 2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "base.hpp"

#include "cpp_helpers.hpp"
#include "test_helpers.h"
#ifndef _WIN32
#include "test_helpers_linux.h"
#endif

#include <umf/memory_provider.h>
#include <umf/pools/pool_proxy.h>
#include <umf/providers/provider_fixed_memory.h>

using umf_test::test;

#define FIXED_BUFFER_SIZE (512 * utils_get_page_size())
#define INVALID_PTR ((void *)0x01)

using providerCreateExtParams = std::tuple<umf_memory_provider_ops_t *, void *>;

static void providerCreateExt(providerCreateExtParams params,
                              umf::provider_unique_handle_t *handle) {
    umf_memory_provider_handle_t hProvider = nullptr;
    auto [provider_ops, provider_params] = params;

    auto ret =
        umfMemoryProviderCreate(provider_ops, provider_params, &hProvider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(hProvider, nullptr);

    *handle =
        umf::provider_unique_handle_t(hProvider, &umfMemoryProviderDestroy);
}

struct TrackingProviderTest
    : umf_test::test,
      ::testing::WithParamInterface<providerCreateExtParams> {
    void SetUp() override {
        test::SetUp();

        // Allocate a memory buffer to use with the fixed memory provider
        memory_size = FIXED_BUFFER_SIZE;
        memory_buffer = malloc(memory_size);
        ASSERT_NE(memory_buffer, nullptr);

        // Create provider parameters
        umf_fixed_memory_provider_params_handle_t params = nullptr;
        umf_result_t res = umfFixedMemoryProviderParamsCreate(
            &params, memory_buffer, memory_size);
        ASSERT_EQ(res, UMF_RESULT_SUCCESS);
        ASSERT_NE(params, nullptr);

        providerCreateExt(std::make_tuple(umfFixedMemoryProviderOps(), params),
                          &provider);

        umfFixedMemoryProviderParamsDestroy(params);
        umf_result_t umf_result =
            umfMemoryProviderGetMinPageSize(provider.get(), NULL, &page_size);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

        page_plus_64 = page_size + 64;

        umf_memory_pool_handle_t hPool = nullptr;
        umf_result = umfPoolCreate(umfProxyPoolOps(), provider.get(), nullptr,
                                   0, &hPool);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

        pool = umf::pool_unique_handle_t(hPool, &umfPoolDestroy);
    }

    void TearDown() override {
        if (memory_buffer) {
            free(memory_buffer);
            memory_buffer = nullptr;
        }
        test::TearDown();
    }

    umf::provider_unique_handle_t provider;
    umf::pool_unique_handle_t pool;
    size_t page_size;
    size_t page_plus_64;
    void *memory_buffer = nullptr;
    size_t memory_size = 0;
};

static void
createPoolFromAllocation(void *ptr0, size_t size1,
                         umf_memory_provider_handle_t *_providerFromPtr,
                         umf_memory_pool_handle_t *_poolFromPtr) {
    umf_result_t umf_result;

    // Create provider parameters
    umf_fixed_memory_provider_params_handle_t params = nullptr;
    umf_result = umfFixedMemoryProviderParamsCreate(&params, ptr0, size1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(params, nullptr);

    umf_memory_provider_handle_t provider1 = nullptr;
    umf_result = umfMemoryProviderCreate(umfFixedMemoryProviderOps(), params,
                                         &provider1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider1, nullptr);

    umf_memory_pool_handle_t pool1 = nullptr;
    umf_result =
        umfPoolCreate(umfProxyPoolOps(), provider1, nullptr, 0, &pool1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umfFixedMemoryProviderParamsDestroy(params);

    *_providerFromPtr = provider1;
    *_poolFromPtr = pool1;
}

// TESTS

INSTANTIATE_TEST_SUITE_P(trackingProviderTest, TrackingProviderTest,
                         ::testing::Values(providerCreateExtParams{
                             umfFixedMemoryProviderOps(), nullptr}));

TEST_P(TrackingProviderTest, create_destroy) {
    // Creation and destruction are handled in SetUp and TearDown
}

TEST_P(TrackingProviderTest, whole_size_success) {
    umf_result_t umf_result;
    size_t size0;
    size_t size1;
    void *ptr0 = nullptr;
    void *ptr1 = nullptr;

    umf_memory_pool_handle_t pool0 = pool.get();

    size0 = FIXED_BUFFER_SIZE - (2 * page_size);
    ptr0 = umfPoolAlignedMalloc(pool0, size0, utils_get_page_size());
    ASSERT_NE(ptr0, nullptr);

    size1 = size0; // whole size

    umf_memory_provider_handle_t provider1 = nullptr;
    umf_memory_pool_handle_t pool1 = nullptr;
    createPoolFromAllocation(ptr0, size1, &provider1, &pool1);

    ptr1 = umfPoolMalloc(pool1, size1);
    ASSERT_NE(ptr1, nullptr);

    umf_result = umfPoolFree(pool1, ptr1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umfPoolDestroy(pool1);
    umfMemoryProviderDestroy(provider1);

    umf_result = umfPoolFree(pool0, ptr0);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
}

TEST_P(TrackingProviderTest, half_size_success) {
    umf_result_t umf_result;
    size_t size0;
    size_t size1;
    void *ptr0 = nullptr;
    void *ptr1 = nullptr;

    umf_memory_pool_handle_t pool0 = pool.get();

    size0 = FIXED_BUFFER_SIZE - (2 * page_size);
    ptr0 = umfPoolAlignedMalloc(pool0, size0, utils_get_page_size());
    ASSERT_NE(ptr0, nullptr);

    size1 = size0 / 2; // half size

    umf_memory_provider_handle_t provider1 = nullptr;
    umf_memory_pool_handle_t pool1 = nullptr;
    createPoolFromAllocation(ptr0, size1, &provider1, &pool1);

    ptr1 = umfPoolMalloc(pool1, size1);
    ASSERT_NE(ptr1, nullptr);

    umf_result = umfPoolFree(pool1, ptr1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umfPoolDestroy(pool1);
    umfMemoryProviderDestroy(provider1);

    umf_result = umfPoolFree(pool0, ptr0);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
}

TEST_P(TrackingProviderTest, failure_exceeding_size) {
    umf_result_t umf_result;
    size_t size0;
    size_t size1;
    void *ptr0 = nullptr;
    void *ptr1 = nullptr;

    umf_memory_pool_handle_t pool0 = pool.get();

    size0 = FIXED_BUFFER_SIZE - (2 * page_size);
    ptr0 = umfPoolAlignedMalloc(pool0, size0, utils_get_page_size());
    ASSERT_NE(ptr0, nullptr);

    size1 = FIXED_BUFFER_SIZE - page_size; // exceeding size

    umf_memory_provider_handle_t provider1 = nullptr;
    umf_memory_pool_handle_t pool1 = nullptr;
    createPoolFromAllocation(ptr0, size1, &provider1, &pool1);

    ptr1 = umfPoolMalloc(pool1, size1);
    ASSERT_EQ(ptr1, nullptr);

    umfPoolDestroy(pool1);
    umfMemoryProviderDestroy(provider1);

    umf_result = umfPoolFree(pool0, ptr0);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
}

#define MAX_ARRAY 9
#define TEST_LEVEL_SUCCESS 7
#define TEST_LEVEL_FAILURE 8

TEST_P(TrackingProviderTest, success_max_levels) {
    umf_result_t umf_result;
    size_t size;
    void *ptr[MAX_ARRAY] = {0};
    umf_memory_provider_handle_t providers[MAX_ARRAY] = {0};
    umf_memory_pool_handle_t pools[MAX_ARRAY] = {0};

    size = FIXED_BUFFER_SIZE - (2 * page_size);
    pools[0] = pool.get();

    for (int i = 0; i < TEST_LEVEL_SUCCESS; i++) {
        fprintf(stderr, "Alloc #%d\n", i);
        ptr[i] = umfPoolAlignedMalloc(pools[i], size, utils_get_page_size());
        ASSERT_NE(ptr[i], nullptr);

        createPoolFromAllocation(ptr[i], size, &providers[i + 1],
                                 &pools[i + 1]);
    }

    int s = TEST_LEVEL_SUCCESS;
    fprintf(stderr, "Alloc #%d\n", s);
    ptr[s] = umfPoolAlignedMalloc(pools[s], size, utils_get_page_size());
    ASSERT_NE(ptr[s], nullptr);

    fprintf(stderr, "Free #%d\n", s);
    umf_result = umfPoolFree(pools[s], ptr[s]);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    for (int i = TEST_LEVEL_SUCCESS - 1; i >= 0; i--) {
        umfPoolDestroy(pools[i + 1]);
        umfMemoryProviderDestroy(providers[i + 1]);

        fprintf(stderr, "Free #%d\n", i);
        umf_result = umfPoolFree(pools[i], ptr[i]);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    }
}

TEST_P(TrackingProviderTest, failure_exceeding_levels) {
    umf_result_t umf_result;
    size_t size;
    void *ptr[MAX_ARRAY] = {0};
    umf_memory_provider_handle_t providers[MAX_ARRAY] = {0};
    umf_memory_pool_handle_t pools[MAX_ARRAY] = {0};

    size = FIXED_BUFFER_SIZE - (2 * page_size);
    pools[0] = pool.get();

    for (int i = 0; i < TEST_LEVEL_FAILURE; i++) {
        fprintf(stderr, "Alloc #%d\n", i);
        ptr[i] = umfPoolAlignedMalloc(pools[i], size, utils_get_page_size());
        ASSERT_NE(ptr[i], nullptr);

        createPoolFromAllocation(ptr[i], size, &providers[i + 1],
                                 &pools[i + 1]);
    }

    // tracker level is too high
    int f = TEST_LEVEL_FAILURE;
    fprintf(stderr, "Alloc #%d\n", f);
    ptr[f] = umfPoolAlignedMalloc(pools[f], size, utils_get_page_size());
    ASSERT_EQ(ptr[f], nullptr);

    for (int i = TEST_LEVEL_FAILURE - 1; i >= 0; i--) {
        umfPoolDestroy(pools[i + 1]);
        umfMemoryProviderDestroy(providers[i + 1]);

        fprintf(stderr, "Free #%d\n", i);
        umf_result = umfPoolFree(pools[i], ptr[i]);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    }
}

TEST_P(TrackingProviderTest, reverted_free_half_size) {
    umf_result_t umf_result;
    size_t size0;
    size_t size1;
    void *ptr0 = nullptr;
    void *ptr1 = nullptr;

    umf_memory_pool_handle_t pool0 = pool.get();

    size0 = FIXED_BUFFER_SIZE - (2 * page_size);
    ptr0 = umfPoolAlignedMalloc(pool0, size0, utils_get_page_size());
    ASSERT_NE(ptr0, nullptr);

    umf_memory_provider_handle_t provider1 = nullptr;
    umf_memory_pool_handle_t pool1 = nullptr;
    createPoolFromAllocation(ptr0, size0, &provider1, &pool1);

    size1 = size0 / 2; // half size

    ptr1 = umfPoolMalloc(pool1, size1);
    ASSERT_NE(ptr1, nullptr);

    // try to free the pointer from the first pool (half size)
    umf_result = umfPoolFree(pool0, ptr0);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umf_result = umfPoolFree(pool1, ptr1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umfPoolDestroy(pool1);
    umfMemoryProviderDestroy(provider1);

    umf_result = umfPoolFree(pool0, ptr0);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
}

TEST_P(TrackingProviderTest, reverted_free_the_same_size) {
    umf_result_t umf_result;
    size_t size0;
    size_t size1;
    void *ptr0 = nullptr;
    void *ptr1 = nullptr;

    umf_memory_pool_handle_t pool0 = pool.get();

    size0 = FIXED_BUFFER_SIZE - (2 * page_size);
    ptr0 = umfPoolAlignedMalloc(pool0, size0, utils_get_page_size());
    ASSERT_NE(ptr0, nullptr);

    umf_memory_provider_handle_t provider1 = nullptr;
    umf_memory_pool_handle_t pool1 = nullptr;
    createPoolFromAllocation(ptr0, size0, &provider1, &pool1);

    size1 = size0; // the same size

    ptr1 = umfPoolMalloc(pool1, size1);
    ASSERT_NE(ptr1, nullptr);

    // try to free the pointer from the first pool (the same size)
    umf_result = umfPoolFree(pool0, ptr0);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    // try to free the pointer from the second pool (the same size)
    umf_result = umfPoolFree(pool1, ptr1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umfPoolDestroy(pool1);
    umfMemoryProviderDestroy(provider1);

    umf_result = umfPoolFree(pool0, ptr0);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}
