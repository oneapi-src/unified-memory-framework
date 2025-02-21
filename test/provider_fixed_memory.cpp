// Copyright (C) 2024-2025 Intel Corporation
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

#define FIXED_BUFFER_SIZE (10 * utils_get_page_size())
#define INVALID_PTR ((void *)0x01)

typedef enum purge_t {
    PURGE_NONE = 0,
    PURGE_LAZY = 1,
    PURGE_FORCE = 2,
} purge_t;

static const char *Native_error_str[] = {
    "success",              // UMF_FIXED_RESULT_SUCCESS
    "force purging failed", // UMF_FIXED_RESULT_ERROR_PURGE_FORCE_FAILED
};

// Test helpers

static int compare_native_error_str(const char *message, int error) {
    const char *error_str = Native_error_str[error - UMF_FIXED_RESULT_SUCCESS];
    size_t len = strlen(error_str);
    return strncmp(message, error_str, len);
}

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

struct FixedProviderTest
    : umf_test::test,
      ::testing::WithParamInterface<providerCreateExtParams> {
    void SetUp() override {
        test::SetUp();

        // Allocate a memory buffer to use with the fixed memory provider
        memory_size = FIXED_BUFFER_SIZE; // Allocate 10 pages
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
    }

    void TearDown() override {
        if (memory_buffer) {
            free(memory_buffer);
            memory_buffer = nullptr;
        }
        test::TearDown();
    }

    void test_alloc_free_success(size_t size, size_t alignment, purge_t purge) {
        void *ptr = nullptr;
        auto provider = this->provider.get();

        umf_result_t umf_result =
            umfMemoryProviderAlloc(provider, size, alignment, &ptr);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        ASSERT_NE(ptr, nullptr);

        memset(ptr, 0xFF, size);

        if (purge == PURGE_LAZY) {
            umf_result = umfMemoryProviderPurgeLazy(provider, ptr, size);
            ASSERT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);
        } else if (purge == PURGE_FORCE) {
            umf_result = umfMemoryProviderPurgeForce(provider, ptr, size);
            ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        }

        umf_result = umfMemoryProviderFree(provider, ptr, size);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    }

    void verify_last_native_error(int32_t err) {
        const char *message;
        int32_t error;
        auto provider = this->provider.get();
        umfMemoryProviderGetLastNativeError(provider, &message, &error);
        ASSERT_EQ(error, err);
        ASSERT_EQ(compare_native_error_str(message, error), 0);
    }

    void test_alloc_failure(size_t size, size_t alignment, umf_result_t result,
                            int32_t err) {
        void *ptr = nullptr;
        auto provider = this->provider.get();

        umf_result_t umf_result =
            umfMemoryProviderAlloc(provider, size, alignment, &ptr);
        ASSERT_EQ(umf_result, result);
        ASSERT_EQ(ptr, nullptr);

        if (umf_result == UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC) {
            verify_last_native_error(err);
        }
    }

    umf::provider_unique_handle_t provider;
    size_t page_size;
    size_t page_plus_64;
    void *memory_buffer = nullptr;
    size_t memory_size = 0;
};

// TESTS

// Positive tests using test_alloc_free_success

INSTANTIATE_TEST_SUITE_P(fixedProviderTest, FixedProviderTest,
                         ::testing::Values(providerCreateExtParams{
                             umfFixedMemoryProviderOps(), nullptr}));

TEST_P(FixedProviderTest, create_destroy) {
    // Creation and destruction are handled in SetUp and TearDown
}

TEST_F(test, create_no_params) {
    umf_memory_provider_handle_t provider = nullptr;
    auto result = umfMemoryProviderCreate(umfFixedMemoryProviderOps(), nullptr,
                                          &provider);
    ASSERT_EQ(result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(provider, nullptr);
}

TEST_P(FixedProviderTest, two_allocations) {
    umf_result_t umf_result;
    void *ptr1 = nullptr;
    void *ptr2 = nullptr;
    size_t size = page_plus_64;
    size_t alignment = page_size;

    umf_result = umfMemoryProviderAlloc(provider.get(), size, alignment, &ptr1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr1, nullptr);

    umf_result = umfMemoryProviderAlloc(provider.get(), size, alignment, &ptr2);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr2, nullptr);

    ASSERT_NE(ptr1, ptr2);
    if ((uintptr_t)ptr1 > (uintptr_t)ptr2) {
        ASSERT_GT((uintptr_t)ptr1 - (uintptr_t)ptr2, size);
    } else {
        ASSERT_GT((uintptr_t)ptr2 - (uintptr_t)ptr1, size);
    }

    memset(ptr1, 0x11, size);
    memset(ptr2, 0x22, size);

    umf_result = umfMemoryProviderFree(provider.get(), ptr1, size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result = umfMemoryProviderFree(provider.get(), ptr2, size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
}

TEST_P(FixedProviderTest, alloc_page64_align_0) {
    test_alloc_free_success(page_plus_64, 0, PURGE_NONE);
}

TEST_P(FixedProviderTest, alloc_page64_align_page_div_2) {
    test_alloc_free_success(page_plus_64, page_size / 2, PURGE_NONE);
}

TEST_P(FixedProviderTest, purge_lazy) {
    test_alloc_free_success(page_size, 0, PURGE_LAZY);
}

TEST_P(FixedProviderTest, purge_force) {
    test_alloc_free_success(page_size, 0, PURGE_FORCE);
}

// Negative tests using test_alloc_failure

TEST_P(FixedProviderTest, alloc_WRONG_SIZE) {
    test_alloc_failure((size_t)-1, 0, UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY, 0);
}

TEST_P(FixedProviderTest, alloc_page64_WRONG_ALIGNMENT_3_pages) {
    test_alloc_failure(page_plus_64, 3 * page_size,
                       UMF_RESULT_ERROR_INVALID_ALIGNMENT, 0);
}

TEST_P(FixedProviderTest, alloc_3pages_WRONG_ALIGNMENT_3pages) {
    test_alloc_failure(3 * page_size, 3 * page_size,
                       UMF_RESULT_ERROR_INVALID_ALIGNMENT, 0);
}

TEST_P(FixedProviderTest, alloc_page64_align_page_plus_1_WRONG_ALIGNMENT_1) {
    test_alloc_failure(page_plus_64, page_size + 1,
                       UMF_RESULT_ERROR_INVALID_ALIGNMENT, 0);
}

TEST_P(FixedProviderTest, alloc_page64_align_one_half_pages_WRONG_ALIGNMENT_2) {
    test_alloc_failure(page_plus_64, page_size + (page_size / 2),
                       UMF_RESULT_ERROR_INVALID_ALIGNMENT, 0);
}

// Other positive tests

TEST_P(FixedProviderTest, get_min_page_size) {
    size_t min_page_size;
    umf_result_t umf_result = umfMemoryProviderGetMinPageSize(
        provider.get(), nullptr, &min_page_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_LE(min_page_size, page_size);
}

TEST_P(FixedProviderTest, get_recommended_page_size) {
    size_t min_page_size;
    umf_result_t umf_result = umfMemoryProviderGetMinPageSize(
        provider.get(), nullptr, &min_page_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_LE(min_page_size, page_size);

    size_t recommended_page_size;
    umf_result = umfMemoryProviderGetRecommendedPageSize(
        provider.get(), 0, &recommended_page_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_GE(recommended_page_size, min_page_size);
}

TEST_P(FixedProviderTest, get_name) {
    const char *name = umfMemoryProviderGetName(provider.get());
    ASSERT_STREQ(name, "FIXED");
}

TEST_P(FixedProviderTest, free_size_0_ptr_not_null) {
    umf_result_t umf_result =
        umfMemoryProviderFree(provider.get(), INVALID_PTR, 0);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_P(FixedProviderTest, free_NULL) {
    umf_result_t umf_result = umfMemoryProviderFree(provider.get(), nullptr, 0);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
}

// Other negative tests

TEST_P(FixedProviderTest, free_INVALID_POINTER_SIZE_GT_0) {
    umf_result_t umf_result =
        umfMemoryProviderFree(provider.get(), INVALID_PTR, page_plus_64);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_P(FixedProviderTest, purge_lazy_INVALID_POINTER) {
    umf_result_t umf_result =
        umfMemoryProviderPurgeLazy(provider.get(), INVALID_PTR, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);
}

TEST_P(FixedProviderTest, purge_force_INVALID_POINTER) {
    umf_result_t umf_result =
        umfMemoryProviderPurgeForce(provider.get(), INVALID_PTR, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC);

    verify_last_native_error(UMF_FIXED_RESULT_ERROR_PURGE_FORCE_FAILED);
}

// Params tests

TEST_F(test, params_null_handle) {
    constexpr size_t memory_size = 100;
    char memory_buffer[memory_size];
    umf_result_t umf_result =
        umfFixedMemoryProviderParamsCreate(nullptr, memory_buffer, memory_size);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umf_result = umfFixedMemoryProviderParamsDestroy(nullptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
}

TEST_F(test, create_with_null_ptr) {
    constexpr size_t memory_size = 100;
    umf_fixed_memory_provider_params_handle_t wrong_params = nullptr;
    umf_result_t umf_result =
        umfFixedMemoryProviderParamsCreate(&wrong_params, nullptr, memory_size);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(wrong_params, nullptr);
}

TEST_F(test, create_with_zero_size) {
    constexpr size_t memory_size = 100;
    char memory_buffer[memory_size];
    umf_fixed_memory_provider_params_handle_t wrong_params = nullptr;
    umf_result_t umf_result =
        umfFixedMemoryProviderParamsCreate(&wrong_params, memory_buffer, 0);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(wrong_params, nullptr);
}

TEST_P(FixedProviderTest, alloc_size_exceeds_buffer) {
    size_t size = memory_size + page_size;
    test_alloc_failure(size, 0, UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY, 0);
}

TEST_P(FixedProviderTest, merge) {
    umf_result_t umf_result;
    void *ptr1 = nullptr;
    void *ptr2 = nullptr;
    size_t size = page_size;
    size_t alignment = page_size;

    umf_result = umfMemoryProviderAlloc(provider.get(), size, alignment, &ptr1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr1, nullptr);

    umf_result = umfMemoryProviderAlloc(provider.get(), size, alignment, &ptr2);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr2, nullptr);

    ASSERT_EQ((uintptr_t)ptr2 - (uintptr_t)ptr1, size);

    memset(ptr1, 0x11, size);
    memset(ptr2, 0x22, size);

    size_t merged_size = size * 2;
    umf_result = umfMemoryProviderAllocationMerge(provider.get(), ptr1, ptr2,
                                                  merged_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result = umfMemoryProviderFree(provider.get(), ptr1, merged_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
}

TEST_P(FixedProviderTest, split) {
    umf_result_t umf_result;
    void *ptr1 = nullptr;
    void *ptr2 = nullptr;
    size_t size = page_size;
    size_t alignment = page_size;

    umf_result =
        umfMemoryProviderAlloc(provider.get(), size * 2, alignment, &ptr1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr1, nullptr);

    umf_result =
        umfMemoryProviderAllocationSplit(provider.get(), ptr1, size * 2, size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    ptr2 = (void *)((uintptr_t)ptr1 + size);
    memset(ptr1, 0x11, size);

    umf_result = umfMemoryProviderFree(provider.get(), ptr1, size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    memset(ptr2, 0x22, size);
    umf_result = umfMemoryProviderFree(provider.get(), ptr2, size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
}

TEST_P(FixedProviderTest, params_set_flags_negative) {
    umf_result_t umf_result;

    // Create provider parameters
    umf_fixed_memory_provider_params_handle_t params = nullptr;
    umf_result =
        umfFixedMemoryProviderParamsCreate(&params, memory_buffer, memory_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(params, nullptr);

    // params is NULL
    umf_result = umfFixedMemoryProviderParamsSetFlags(
        NULL, UMF_FIXED_FLAG_CREATE_FROM_POOL_PTR);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // the pointer does not belong to any UMF pool
    umf_result = umfFixedMemoryProviderParamsSetFlags(
        params, UMF_FIXED_FLAG_CREATE_FROM_POOL_PTR);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umfFixedMemoryProviderParamsDestroy(params);
}

TEST_P(FixedProviderTest, pool_from_ptr_negative_wrong_ptr) {
    umf_result_t umf_result;
    size_t size_of_first_alloc;
    size_t size_of_pool_from_ptr;
    void *ptr_for_pool = nullptr;

    umf_memory_pool_handle_t proxyFixedPool = nullptr;
    umf_result = umfPoolCreate(umfProxyPoolOps(), provider.get(), nullptr, 0,
                               &proxyFixedPool);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    size_of_first_alloc = FIXED_BUFFER_SIZE - (2 * page_size);
    ptr_for_pool = umfPoolMalloc(proxyFixedPool, size_of_first_alloc);
    ASSERT_NE(ptr_for_pool, nullptr);

    // Create provider parameters
    size_of_pool_from_ptr = size_of_first_alloc; // whole size
    umf_fixed_memory_provider_params_handle_t params = nullptr;
    umf_result = umfFixedMemoryProviderParamsCreate(&params, ptr_for_pool,
                                                    size_of_pool_from_ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(params, nullptr);

    umf_result = umfFixedMemoryProviderParamsSetFlags(
        params, UMF_FIXED_FLAG_CREATE_FROM_POOL_PTR);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result = umfPoolFree(proxyFixedPool, ptr_for_pool);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    // the pointer (ptr_for_pool) does not belong to any UMF pool
    umf_memory_provider_handle_t providerFromPtr = nullptr;
    umf_result = umfMemoryProviderCreate(umfFixedMemoryProviderOps(), params,
                                         &providerFromPtr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(providerFromPtr, nullptr);

    umfFixedMemoryProviderParamsDestroy(params);
    umfPoolDestroy(proxyFixedPool);
}

TEST_P(FixedProviderTest, pool_from_ptr_negative_shrink_size_too_big) {
    umf_result_t umf_result;
    size_t size_of_first_alloc;
    size_t size_of_pool_from_ptr;
    void *ptr_for_pool = nullptr;

    umf_memory_pool_handle_t proxyFixedPool = nullptr;
    umf_result = umfPoolCreate(umfProxyPoolOps(), provider.get(), nullptr, 0,
                               &proxyFixedPool);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    size_of_first_alloc = FIXED_BUFFER_SIZE - (2 * page_size);
    ptr_for_pool = umfPoolMalloc(proxyFixedPool, size_of_first_alloc);
    ASSERT_NE(ptr_for_pool, nullptr);

    // Create provider parameters
    size_of_pool_from_ptr = size_of_first_alloc + 1; // size too big
    umf_fixed_memory_provider_params_handle_t params = nullptr;
    umf_result = umfFixedMemoryProviderParamsCreate(&params, ptr_for_pool,
                                                    size_of_pool_from_ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(params, nullptr);

    umf_result = umfFixedMemoryProviderParamsSetFlags(
        params, UMF_FIXED_FLAG_CREATE_FROM_POOL_PTR);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_memory_provider_handle_t providerFromPtr = nullptr;
    umf_result = umfMemoryProviderCreate(umfFixedMemoryProviderOps(), params,
                                         &providerFromPtr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(providerFromPtr, nullptr);

    umfFixedMemoryProviderParamsDestroy(params);

    umf_result = umfPoolFree(proxyFixedPool, ptr_for_pool);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umfPoolDestroy(proxyFixedPool);
}

TEST_P(FixedProviderTest, pool_from_ptr_whole_size_success) {
    umf_result_t umf_result;
    size_t size_of_first_alloc;
    size_t size_of_pool_from_ptr;
    void *ptr_for_pool = nullptr;
    void *ptr = nullptr;

    umf_memory_pool_handle_t proxyFixedPool = nullptr;
    umf_result = umfPoolCreate(umfProxyPoolOps(), provider.get(), nullptr, 0,
                               &proxyFixedPool);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    size_of_first_alloc = FIXED_BUFFER_SIZE - (2 * page_size);
    ptr_for_pool = umfPoolMalloc(proxyFixedPool, size_of_first_alloc);
    ASSERT_NE(ptr_for_pool, nullptr);

    // Create provider parameters
    size_of_pool_from_ptr = size_of_first_alloc; // whole size
    umf_fixed_memory_provider_params_handle_t params = nullptr;
    umf_result = umfFixedMemoryProviderParamsCreate(&params, ptr_for_pool,
                                                    size_of_pool_from_ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(params, nullptr);

    umf_result = umfFixedMemoryProviderParamsSetFlags(
        params, UMF_FIXED_FLAG_CREATE_FROM_POOL_PTR);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_memory_provider_handle_t providerFromPtr = nullptr;
    umf_result = umfMemoryProviderCreate(umfFixedMemoryProviderOps(), params,
                                         &providerFromPtr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(providerFromPtr, nullptr);

    umf_memory_pool_handle_t poolFromPtr = nullptr;
    umf_result = umfPoolCreate(umfProxyPoolOps(), providerFromPtr, nullptr, 0,
                               &poolFromPtr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    ptr = umfPoolMalloc(poolFromPtr, size_of_pool_from_ptr);
    ASSERT_NE(ptr, nullptr);

    memset(ptr, 0xFF, size_of_pool_from_ptr);

    umf_result = umfPoolFree(poolFromPtr, ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umfPoolDestroy(poolFromPtr);
    umfMemoryProviderDestroy(providerFromPtr);
    umfFixedMemoryProviderParamsDestroy(params);

    umf_result = umfPoolFree(proxyFixedPool, ptr_for_pool);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umfPoolDestroy(proxyFixedPool);
}

TEST_P(FixedProviderTest, pool_from_ptr_half_size_success) {
    umf_result_t umf_result;
    size_t size_of_first_alloc;
    size_t size_of_pool_from_ptr;
    void *ptr_for_pool = nullptr;
    void *ptr = nullptr;

    umf_memory_pool_handle_t proxyFixedPool = nullptr;
    umf_result = umfPoolCreate(umfProxyPoolOps(), provider.get(), nullptr, 0,
                               &proxyFixedPool);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    size_of_first_alloc = FIXED_BUFFER_SIZE - (2 * page_size);
    ptr_for_pool = umfPoolMalloc(proxyFixedPool, size_of_first_alloc);
    ASSERT_NE(ptr_for_pool, nullptr);

    // Create provider parameters
    size_of_pool_from_ptr = size_of_first_alloc / 2; // half size
    umf_fixed_memory_provider_params_handle_t params = nullptr;
    umf_result = umfFixedMemoryProviderParamsCreate(&params, ptr_for_pool,
                                                    size_of_pool_from_ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(params, nullptr);

    umf_result = umfFixedMemoryProviderParamsSetFlags(
        params, UMF_FIXED_FLAG_CREATE_FROM_POOL_PTR);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_memory_provider_handle_t providerFromPtr = nullptr;
    umf_result = umfMemoryProviderCreate(umfFixedMemoryProviderOps(), params,
                                         &providerFromPtr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(providerFromPtr, nullptr);

    umf_memory_pool_handle_t poolFromPtr = nullptr;
    umf_result = umfPoolCreate(umfProxyPoolOps(), providerFromPtr, nullptr, 0,
                               &poolFromPtr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    ptr = umfPoolMalloc(poolFromPtr, size_of_pool_from_ptr);
    ASSERT_NE(ptr, nullptr);

    memset(ptr, 0xFF, size_of_pool_from_ptr);

    umf_result = umfPoolFree(poolFromPtr, ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umfPoolDestroy(poolFromPtr);
    umfMemoryProviderDestroy(providerFromPtr);
    umfFixedMemoryProviderParamsDestroy(params);

    umf_result = umfPoolFree(proxyFixedPool, ptr_for_pool);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umfPoolDestroy(proxyFixedPool);
}
