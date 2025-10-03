// Copyright (C) 2024-2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#endif

#include <umf/experimental/ctl.h>
#include <umf/memory_provider.h>
#include <umf/providers/provider_devdax_memory.h>

#include "base.hpp"
#include "provider.hpp"
#include "test_helpers.h"
#include "utils/cpp_helpers.hpp"
#ifndef _WIN32
#include "test_helpers_linux.h"
#endif

using umf_test::test;

#define INVALID_PTR ((void *)0x01)

typedef enum purge_t {
    PURGE_NONE = 0,
    PURGE_LAZY = 1,
    PURGE_FORCE = 2,
} purge_t;

static const char *Native_error_str[] = {
    "success",                          // UMF_DEVDAX_RESULT_SUCCESS
    "memory allocation failed",         // UMF_DEVDAX_RESULT_ERROR_ALLOC_FAILED
    "allocated address is not aligned", // UMF_DEVDAX_RESULT_ERROR_ADDRESS_NOT_ALIGNED
    "memory deallocation failed",       // UMF_DEVDAX_RESULT_ERROR_FREE_FAILED
    "force purging failed", // UMF_DEVDAX_RESULT_ERROR_PURGE_FORCE_FAILED
};

// test helpers

static int compare_native_error_str(const char *message, int error) {
    const char *error_str = Native_error_str[error - UMF_DEVDAX_RESULT_SUCCESS];
    size_t len = strlen(error_str);
    return strncmp(message, error_str, len);
}

struct umfProviderTest
    : umf_test::test,
      ::testing::WithParamInterface<providerCreateExtParams> {
    void SetUp() override {
        test::SetUp();
        providerCreateExt(this->GetParam(), &provider);
        umf_result_t umf_result = umfMemoryProviderGetMinPageSize(
            provider.get(), nullptr, &page_size);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

        page_plus_64 = page_size + 64;
    }

    void TearDown() override { test::TearDown(); }

    umf_test::provider_unique_handle_t provider;
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
        ASSERT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);
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
    umf_result_t ret =
        umfMemoryProviderGetLastNativeError(provider, &message, &error);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
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

// Test checking if devdax was mapped with the MAP_SYNC flag:
TEST_F(test, test_if_mapped_with_MAP_SYNC) {
    umf_memory_provider_handle_t hProvider = nullptr;
    umf_result_t umf_result;

    char *path = getenv("UMF_TESTS_DEVDAX_PATH");
    if (path == nullptr || path[0] == '\0') {
        GTEST_SKIP() << "Test skipped, UMF_TESTS_DEVDAX_PATH is not set";
    }

    char *size_str = getenv("UMF_TESTS_DEVDAX_SIZE");
    if (size_str == nullptr || size_str[0] == 0) {
        GTEST_SKIP() << "Test skipped, UMF_TESTS_DEVDAX_SIZE is not set";
    }

    size_t size = atol(size_str);
    umf_devdax_memory_provider_params_handle_t params = NULL;
    umf_result = umfDevDaxMemoryProviderParamsCreate(path, size, &params);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(params, nullptr);

    umf_result = umfMemoryProviderCreate(umfDevDaxMemoryProviderOps(), params,
                                         &hProvider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(hProvider, nullptr);

    char *buf;
    umf_result = umfMemoryProviderAlloc(hProvider, size, 0, (void **)&buf);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(buf, nullptr);

    bool flag_found = is_mapped_with_MAP_SYNC(path, buf, size);

    umf_result = umfMemoryProviderFree(hProvider, buf, size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umfMemoryProviderDestroy(hProvider);
    umfDevDaxMemoryProviderParamsDestroy(params);

    // fail test if the "sf" flag was not found
    ASSERT_EQ(flag_found, true);
}

// positive tests using test_alloc_free_success

using devdax_params_unique_handle_t =
    std::unique_ptr<umf_devdax_memory_provider_params_t,
                    decltype(&umfDevDaxMemoryProviderParamsDestroy)>;

devdax_params_unique_handle_t create_devdax_params() {
    char *path = getenv("UMF_TESTS_DEVDAX_PATH");
    char *size = getenv("UMF_TESTS_DEVDAX_SIZE");
    if (path == nullptr || path[0] == '\0' || size == nullptr ||
        size[0] == '\0') {
        return devdax_params_unique_handle_t(
            nullptr, &umfDevDaxMemoryProviderParamsDestroy);
    }

    umf_devdax_memory_provider_params_handle_t params = NULL;
    umf_result_t res =
        umfDevDaxMemoryProviderParamsCreate(path, atol(size), &params);
    if (res != UMF_RESULT_SUCCESS) {
        throw std::runtime_error(
            "Failed to create DevDax Memory Provider params");
    }

    return devdax_params_unique_handle_t(params,
                                         &umfDevDaxMemoryProviderParamsDestroy);
}

auto defaultDevDaxParams = create_devdax_params();

static std::vector<providerCreateExtParams> devdaxProviderTestParamsList =
    defaultDevDaxParams.get()
        ? std::vector<providerCreateExtParams>{providerCreateExtParams{
              umfDevDaxMemoryProviderOps(), defaultDevDaxParams.get()}}
        : std::vector<providerCreateExtParams>{};

GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfProviderTest);

INSTANTIATE_TEST_SUITE_P(devdaxProviderTest, umfProviderTest,
                         ::testing::ValuesIn(devdaxProviderTestParamsList),
                         providerCreateExtParamsNameGen);

TEST_P(umfProviderTest, create_destroy) {}

TEST_P(umfProviderTest, alloc_page_align_0) {
    test_alloc_free_success(provider.get(), page_size, 0, PURGE_NONE);
}

TEST_P(umfProviderTest, alloc_2page_align_page_size) {
    test_alloc_free_success(provider.get(), 2 * page_size, page_size,
                            PURGE_NONE);
}

TEST_P(umfProviderTest, alloc_page64_align_page_div_2) {
    test_alloc_free_success(provider.get(), page_plus_64, page_size / 2,
                            PURGE_NONE);
}

TEST_P(umfProviderTest, purge_lazy) {
    test_alloc_free_success(provider.get(), page_size, 0, PURGE_LAZY);
}

TEST_P(umfProviderTest, purge_force) {
    test_alloc_free_success(provider.get(), page_size, 0, PURGE_FORCE);
}

TEST_P(umfProviderTest, purge_force_unaligned_alloc) {
    void *ptr;
    auto ret = umfMemoryProviderAlloc(provider.get(), page_plus_64, 0, &ptr);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    test_alloc_free_success(provider.get(), page_size, 0, PURGE_FORCE);
    umfMemoryProviderFree(provider.get(), ptr, page_plus_64);
}
// negative tests using test_alloc_failure

TEST_P(umfProviderTest, alloc_page64_align_page_minus_1_WRONG_ALIGNMENT_1) {
    test_alloc_failure(provider.get(), page_plus_64, page_size - 1,
                       UMF_RESULT_ERROR_INVALID_ALIGNMENT, 0);
}

TEST_P(umfProviderTest, alloc_page64_align_one_half_pages_WRONG_ALIGNMENT_2) {
    test_alloc_failure(provider.get(), page_plus_64,
                       page_size + (page_size / 2),
                       UMF_RESULT_ERROR_INVALID_ALIGNMENT, 0);
}

TEST_P(umfProviderTest, alloc_page64_WRONG_ALIGNMENT_3_pages) {
    test_alloc_failure(provider.get(), page_plus_64, 3 * page_size,
                       UMF_RESULT_ERROR_INVALID_ALIGNMENT, 0);
}

TEST_P(umfProviderTest, alloc_3_pages_WRONG_ALIGNMENT_3_pages) {
    test_alloc_failure(provider.get(), 3 * page_size, 3 * page_size,
                       UMF_RESULT_ERROR_INVALID_ALIGNMENT, 0);
}

TEST_P(umfProviderTest, alloc_WRONG_SIZE) {
    size_t size = (size_t)(-1) & ~(page_size - 1);
    test_alloc_failure(provider.get(), size, 0,
                       UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY, 0);
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
    const char *name = nullptr;
    umf_result_t ret = umfMemoryProviderGetName(provider.get(), &name);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_STREQ(name, "DEVDAX");
}

TEST(DevDaxProviderName, custom_name) {
    auto params_handle = create_devdax_params();
    if (!params_handle.get()) {
        GTEST_SKIP() << "devdax params unavailable";
    }

    const char *custom = "my_devdax";
    auto ret =
        umfDevDaxMemoryProviderParamsSetName(params_handle.get(), custom);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    umf_memory_provider_handle_t prov = nullptr;
    ret = umfMemoryProviderCreate(umfDevDaxMemoryProviderOps(),
                                  params_handle.get(), &prov);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    const char *name = nullptr;
    ret = umfMemoryProviderGetName(prov, &name);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    EXPECT_STREQ(name, custom);
    umfMemoryProviderDestroy(prov);
}

TEST(DevDaxProviderName, default_name_null_handle) {
    const char *name = nullptr;
    EXPECT_EQ(umfDevDaxMemoryProviderOps()->get_name(nullptr, &name),
              UMF_RESULT_SUCCESS);
    EXPECT_STREQ(name, "DEVDAX");
}

TEST_P(umfProviderTest, free_size_0_ptr_not_null) {
    umf_result_t umf_result =
        umfMemoryProviderFree(provider.get(), INVALID_PTR, 0);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_P(umfProviderTest, free_NULL) {
    umf_result_t umf_result = umfMemoryProviderFree(provider.get(), nullptr, 0);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
}

TEST_P(umfProviderTest, ctl_stats) {
    size_t allocated = 0, peak = 0;
    umf_result_t ret =
        umfCtlGet("umf.provider.by_handle.{}.stats.allocated_memory",
                  &allocated, sizeof(allocated), provider.get());
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(allocated, 0u);

    ret = umfCtlGet("umf.provider.by_handle.{}.stats.peak_memory", &peak,
                    sizeof(peak), provider.get());
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(peak, 0u);

    void *ptr = nullptr;
    size_t size = page_size;
    ret = umfMemoryProviderAlloc(provider.get(), size, 0, &ptr);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    ret = umfCtlGet("umf.provider.by_handle.{}.stats.allocated_memory",
                    &allocated, sizeof(allocated), provider.get());
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(allocated, size);

    ret = umfCtlGet("umf.provider.by_handle.{}.stats.peak_memory", &peak,
                    sizeof(peak), provider.get());
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(peak, size);

    ret = umfMemoryProviderFree(provider.get(), ptr, size);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfCtlGet("umf.provider.by_handle.{}.stats.allocated_memory",
                    &allocated, sizeof(allocated), provider.get());
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(allocated, 0u);

    ret = umfCtlGet("umf.provider.by_handle.{}.stats.peak_memory", &peak,
                    sizeof(peak), provider.get());
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(peak, size);

    ret = umfCtlExec("umf.provider.by_handle.{}.stats.peak_memory.reset", NULL,
                     0, provider.get());
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfCtlGet("umf.provider.by_handle.{}.stats.peak_memory", &peak,
                    sizeof(peak), provider.get());
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(peak, 0u);
}

// other negative tests

TEST_P(umfProviderTest, free_INVALID_POINTER_SIZE_GT_0) {
    umf_result_t umf_result =
        umfMemoryProviderFree(provider.get(), INVALID_PTR, page_plus_64);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_P(umfProviderTest, purge_lazy_INVALID_POINTER) {
    umf_result_t umf_result =
        umfMemoryProviderPurgeLazy(provider.get(), INVALID_PTR, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);
}

TEST_P(umfProviderTest, purge_force_INVALID_POINTER) {
    umf_result_t umf_result =
        umfMemoryProviderPurgeForce(provider.get(), INVALID_PTR, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC);

    verify_last_native_error(provider.get(),
                             UMF_DEVDAX_RESULT_ERROR_PURGE_FORCE_FAILED);
}

// params tests

TEST_F(test, params_protection_flag) {
    umf_devdax_memory_provider_params_handle_t params = nullptr;
    umf_result_t ret =
        umfDevDaxMemoryProviderParamsCreate("/dev/dax0.0", 4096, &params);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(params, nullptr);

    //test all valid combinations
    for (unsigned protection = UMF_PROTECTION_NONE;
         protection < (UMF_PROTECTION_MAX - 1) << 1; ++protection) {
        ret = umfDevDaxMemoryProviderParamsSetProtection(params, protection);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    }

    umfDevDaxMemoryProviderParamsDestroy(params);
}

// negative params tests

TEST_F(test, params_invalid_protection_flag) {
    umf_devdax_memory_provider_params_handle_t params = nullptr;
    umf_result_t ret =
        umfDevDaxMemoryProviderParamsCreate("/dev/dax0.0", 4096, &params);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(params, nullptr);

    ret = umfDevDaxMemoryProviderParamsSetProtection(params, 0);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    for (unsigned protection = UMF_PROTECTION_NONE;
         protection < (UMF_PROTECTION_MAX - 1) << 1; ++protection) {
        unsigned invalid_protection = protection | (UMF_PROTECTION_MAX << 1);
        ret = umfDevDaxMemoryProviderParamsSetProtection(params,
                                                         invalid_protection);
        ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    }

    umfDevDaxMemoryProviderParamsDestroy(params);
}

TEST_F(test, params_null_handle) {
    auto ret =
        umfDevDaxMemoryProviderParamsCreate("/dev/dax0.0", 4096, nullptr);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = umfDevDaxMemoryProviderParamsDestroy(nullptr);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    ret =
        umfDevDaxMemoryProviderParamsSetDeviceDax(nullptr, "/dev/dax0.0", 4096);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = umfDevDaxMemoryProviderParamsSetProtection(nullptr, 1);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_F(test, create_empty_path) {
    const char *path = "";
    umf_devdax_memory_provider_params_handle_t wrong_params = NULL;
    auto ret = umfDevDaxMemoryProviderParamsCreate(path, 4096, &wrong_params);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(wrong_params, nullptr);
}

TEST_F(test, create_null_path) {
    const char *path = nullptr;
    umf_devdax_memory_provider_params_handle_t wrong_params = NULL;
    auto ret = umfDevDaxMemoryProviderParamsCreate(path, 4096, &wrong_params);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(wrong_params, nullptr);
}

TEST_F(test, set_empty_path) {
    const char *path = "tmp";
    const char *empty_path = "";
    umf_devdax_memory_provider_params_handle_t params = NULL;
    auto ret = umfDevDaxMemoryProviderParamsCreate(path, 4096, &params);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(params, nullptr);

    ret = umfDevDaxMemoryProviderParamsSetDeviceDax(params, empty_path, 4096);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = umfDevDaxMemoryProviderParamsDestroy(params);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
}

TEST_F(test, set_null_path) {
    const char *path = "tmp";
    const char *null_path = nullptr;
    umf_devdax_memory_provider_params_handle_t params = NULL;
    auto ret = umfDevDaxMemoryProviderParamsCreate(path, 4096, &params);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(params, nullptr);

    ret = umfDevDaxMemoryProviderParamsSetDeviceDax(params, null_path, 4096);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = umfDevDaxMemoryProviderParamsDestroy(params);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
}

TEST_F(test, create_wrong_path) {
    umf_memory_provider_handle_t hProvider = nullptr;
    const char *path = "/tmp/dev/dax0.0";
    umf_devdax_memory_provider_params_handle_t wrong_params = nullptr;

    auto ret = umfDevDaxMemoryProviderParamsCreate(path, 4096, &wrong_params);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(wrong_params, nullptr);

    ret = umfMemoryProviderCreate(umfDevDaxMemoryProviderOps(), wrong_params,
                                  &hProvider);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(hProvider, nullptr);

    ret = umfDevDaxMemoryProviderParamsDestroy(wrong_params);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
}

TEST_F(test, create_wrong_path_not_exist) {
    umf_memory_provider_handle_t hProvider = nullptr;
    const char *path = "/dev/dax1.1";
    umf_devdax_memory_provider_params_handle_t wrong_params = nullptr;

    auto ret = umfDevDaxMemoryProviderParamsCreate(path, 4096, &wrong_params);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(wrong_params, nullptr);

    ret = umfMemoryProviderCreate(umfDevDaxMemoryProviderOps(), wrong_params,
                                  &hProvider);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(hProvider, nullptr);

    ret = umfDevDaxMemoryProviderParamsDestroy(wrong_params);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
}

TEST_F(test, create_wrong_size_0) {
    umf_memory_provider_handle_t hProvider = nullptr;
    const char *path = "/dev/dax0.0";
    umf_devdax_memory_provider_params_handle_t wrong_params = nullptr;

    auto ret = umfDevDaxMemoryProviderParamsCreate(path, 0, &wrong_params);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(wrong_params, nullptr);

    ret = umfMemoryProviderCreate(umfDevDaxMemoryProviderOps(), wrong_params,
                                  &hProvider);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(hProvider, nullptr);

    ret = umfDevDaxMemoryProviderParamsDestroy(wrong_params);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
}

TEST_F(test, create_NULL_params) {
    umf_memory_provider_handle_t hProvider = nullptr;
    auto ret = umfMemoryProviderCreate(umfDevDaxMemoryProviderOps(), nullptr,
                                       &hProvider);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(hProvider, nullptr);
}

TEST_F(test, params_NULL_name) {
    umf_devdax_memory_provider_params_handle_t params = nullptr;
    auto ret =
        umfDevDaxMemoryProviderParamsCreate("/dev/dax0.0", 4096, &params);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(params, nullptr);

    ret = umfDevDaxMemoryProviderParamsSetName(params, nullptr);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = umfDevDaxMemoryProviderParamsDestroy(params);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfDevDaxMemoryProviderParamsSetName(nullptr, "test");
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_F(test, get_NULL_name) {
    umf_devdax_memory_provider_params_handle_t params =
        defaultDevDaxParams.get();
    ASSERT_NE(params, nullptr);

    umf_memory_provider_handle_t hProvider = nullptr;
    umf_result_t ret = umfMemoryProviderCreate(umfDevDaxMemoryProviderOps(),
                                               params, &hProvider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(hProvider, nullptr);

    ret = umfMemoryProviderGetName(hProvider, NULL);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = umfMemoryProviderDestroy(hProvider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfDevDaxMemoryProviderParamsDestroy(params);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
}
