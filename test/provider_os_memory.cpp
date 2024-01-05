// Copyright (C) 2023 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "base.hpp"

#include "cpp_helpers.hpp"
#include "provider_os_memory_internal.h"
#include "umf/providers/provider_os_memory.h"
#include <umf/memory_provider.h>

using umf_test::test;

#define INVALID_PTR ((void *)0x01)

#define ASSERT_IS_ALIGNED(ptr, alignment)                                      \
    ASSERT_EQ(((uintptr_t)ptr % alignment), 0)

typedef enum purge_t {
    PURGE_NONE = 0,
    PURGE_LAZY = 1,
    PURGE_FORCE = 2,
} purge_t;

static umf_os_memory_provider_params_t UMF_OS_MEMORY_PROVIDER_PARAMS_TEST = {
    /* .protection = */ UMF_PROTECTION_READ | UMF_PROTECTION_WRITE,
    /* .visibility = */ UMF_VISIBILITY_PRIVATE,

    // NUMA config
    /* .nodemask = */ NULL,
    /* .maxnode = */ 0,
    /* .numa_mode = */ UMF_NUMA_MODE_DEFAULT,
    /* .numa_flags = */ 0,

    // others
    /* .traces = */ 1,
};

static const char *Native_error_str[] = {
    "success",                          // UMF_OS_RESULT_SUCCESS
    "memory allocation failed",         // UMF_OS_RESULT_ERROR_ALLOC_FAILED
    "allocated address is not aligned", // UMF_OS_RESULT_ERROR_ADDRESS_NOT_ALIGNED
    "binding memory to NUMA node failed", // UMF_OS_RESULT_ERROR_BIND_FAILED
    "memory deallocation failed",         // UMF_OS_RESULT_ERROR_FREE_FAILED
    "lazy purging failed",  // UMF_OS_RESULT_ERROR_PURGE_LAZY_FAILED
    "force purging failed", // UMF_OS_RESULT_ERROR_PURGE_FORCE_FAILED
};

// test helpers

static int compare_native_error_str(const char *message, int error) {
    const char *error_str = Native_error_str[error - UMF_OS_RESULT_SUCCESS];
    size_t len = strlen(error_str);
    return strncmp(message, error_str, len);
}

using providerCreateExtParams = std::tuple<umf_memory_provider_ops_t *, void *>;

umf::provider_unique_handle_t
providerCreateExt(providerCreateExtParams params) {
    umf_memory_provider_handle_t hProvider;
    auto [provider_ops, provider_params] = params;

    auto ret =
        umfMemoryProviderCreate(provider_ops, provider_params, &hProvider);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    EXPECT_NE(hProvider, nullptr);

    return umf::provider_unique_handle_t(hProvider, &umfMemoryProviderDestroy);
}

struct umfProviderTest
    : umf_test::test,
      ::testing::WithParamInterface<providerCreateExtParams> {
    void SetUp() override {
        test::SetUp();
        provider = providerCreateExt(this->GetParam());
        umf_result_t umf_result =
            umfMemoryProviderGetMinPageSize(provider.get(), NULL, &page_size);
        EXPECT_EQ(umf_result, UMF_RESULT_SUCCESS);

        page_plus_64 = page_size + 64;
    }

    void TearDown() override { test::TearDown(); }

    umf::provider_unique_handle_t provider;
    size_t page_size;
    size_t page_plus_64;
};

static void test_alloc_free_success(umf_memory_provider_handle_t provider,
                                    size_t size, size_t alignment,
                                    purge_t purge) {
    void *ptr = nullptr;

    umf_result_t umf_result =
        umfMemoryProviderAlloc(provider, size, alignment, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    memset(ptr, 0xFF, size);

    if (purge == PURGE_LAZY) {
        umf_result = umfMemoryProviderPurgeLazy(provider, ptr, size);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    } else if (purge == PURGE_FORCE) {
        umf_result = umfMemoryProviderPurgeForce(provider, ptr, size);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    }

    umf_result = umfMemoryProviderFree(provider, ptr, size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
}

static void verify_last_native_error(umf_memory_provider_handle_t provider,
                                     int32_t err) {
    const char *message;
    int32_t error;
    umfMemoryProviderGetLastNativeError(provider, &message, &error);
    ASSERT_EQ(error, err);
    ASSERT_EQ(compare_native_error_str(message, error), 0);
}

static void test_alloc_failure(umf_memory_provider_handle_t provider,
                               size_t size, size_t alignment,
                               umf_result_t result, int32_t err) {
    void *ptr = nullptr;
    umf_result_t umf_result =
        umfMemoryProviderAlloc(provider, size, alignment, &ptr);
    ASSERT_EQ(umf_result, result);
    ASSERT_EQ(ptr, nullptr);

    if (umf_result == UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC) {
        verify_last_native_error(provider, err);
    }
}

// TESTS

// negative tests for umfMemoryProviderCreate()

TEST_F(test, create_WRONG_NUMA_MODE) {
    umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = nullptr;
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;

    // NUMA binding mode not supported for UMF_VISIBILITY_SHARED
    os_memory_provider_params.visibility = UMF_VISIBILITY_SHARED;
    os_memory_provider_params.numa_mode = UMF_NUMA_MODE_BIND;

    umf_result = umfMemoryProviderCreate(&UMF_OS_MEMORY_PROVIDER_OPS,
                                         &os_memory_provider_params,
                                         &os_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(os_memory_provider, nullptr);
}

TEST_F(test, create_WRONG_NUMA_FLAGS) {
    umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = nullptr;
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;

    // wrong NUMA flags
    os_memory_provider_params.numa_flags = (unsigned int)-1;

    umf_result = umfMemoryProviderCreate(&UMF_OS_MEMORY_PROVIDER_OPS,
                                         &os_memory_provider_params,
                                         &os_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(os_memory_provider, nullptr);
}

// positive tests using test_alloc_free_success

INSTANTIATE_TEST_SUITE_P(osProviderTest, umfProviderTest,
                         ::testing::Values(providerCreateExtParams{
                             &UMF_OS_MEMORY_PROVIDER_OPS,
                             &UMF_OS_MEMORY_PROVIDER_PARAMS_TEST}));

TEST_P(umfProviderTest, create_destroy) {}

TEST_P(umfProviderTest, alloc_page64_align_0) {
    test_alloc_free_success(provider.get(), page_plus_64, 0, PURGE_NONE);
}

TEST_P(umfProviderTest, alloc_page64_align_page_div_2) {
    test_alloc_free_success(provider.get(), page_plus_64, page_size / 2,
                            PURGE_NONE);
}

TEST_P(umfProviderTest, alloc_page64_align_3_pages) {
    test_alloc_free_success(provider.get(), page_plus_64, 3 * page_size,
                            PURGE_NONE);
}

TEST_P(umfProviderTest, alloc_3pages_align_3pages) {
    test_alloc_free_success(provider.get(), 3 * page_size, 3 * page_size,
                            PURGE_NONE);
}

TEST_P(umfProviderTest, purge_lazy) {
    test_alloc_free_success(provider.get(), page_plus_64, 0, PURGE_LAZY);
}

TEST_P(umfProviderTest, purge_force) {
    test_alloc_free_success(provider.get(), page_plus_64, 0, PURGE_FORCE);
}

// negative tests using test_alloc_failure

TEST_P(umfProviderTest, alloc_page64_align_page_minus_1_WRONG_ALIGNMENT_1) {
    test_alloc_failure(provider.get(), page_plus_64, page_size - 1,
                       UMF_RESULT_ERROR_INVALID_ARGUMENT, 0);
}

TEST_P(umfProviderTest, alloc_page64_align_one_half_pages_WRONG_ALIGNMENT_2) {
    test_alloc_failure(provider.get(), page_plus_64,
                       page_size + (page_size / 2),
                       UMF_RESULT_ERROR_INVALID_ARGUMENT, 0);
}

TEST_P(umfProviderTest, alloc_WRONG_SIZE) {
    test_alloc_failure(provider.get(), -1, 0,
                       UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC,
                       UMF_OS_RESULT_ERROR_ALLOC_FAILED);
}

// other positive tests

TEST_P(umfProviderTest, get_min_page_size) {
    size_t min_page_size;
    umf_result_t umf_result = umfMemoryProviderGetMinPageSize(
        provider.get(), nullptr, &min_page_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_LE(min_page_size, page_size);
}

TEST_P(umfProviderTest, get_recommended_page_size) {
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

TEST_P(umfProviderTest, get_name) {
    const char *name = umfMemoryProviderGetName(provider.get());
    ASSERT_STREQ(name, "OS");
}

TEST_P(umfProviderTest, free_size_0_ptr_not_null) {
    umf_result_t umf_result =
        umfMemoryProviderFree(provider.get(), INVALID_PTR, 0);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
}

// other negative tests

TEST_P(umfProviderTest, free_NULL) {
    umf_result_t umf_result = umfMemoryProviderFree(provider.get(), nullptr, 0);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_P(umfProviderTest, free_INVALID_POINTER_SIZE_GT_0) {
    umf_result_t umf_result =
        umfMemoryProviderFree(provider.get(), INVALID_PTR, page_plus_64);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC);

    verify_last_native_error(provider.get(), UMF_OS_RESULT_ERROR_FREE_FAILED);
}

TEST_P(umfProviderTest, purge_lazy_INVALID_POINTER) {
    umf_result_t umf_result =
        umfMemoryProviderPurgeLazy(provider.get(), INVALID_PTR, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC);

    verify_last_native_error(provider.get(),
                             UMF_OS_RESULT_ERROR_PURGE_LAZY_FAILED);
}

TEST_P(umfProviderTest, purge_force_INVALID_POINTER) {
    umf_result_t umf_result =
        umfMemoryProviderPurgeForce(provider.get(), INVALID_PTR, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC);

    verify_last_native_error(provider.get(),
                             UMF_OS_RESULT_ERROR_PURGE_FORCE_FAILED);
}
