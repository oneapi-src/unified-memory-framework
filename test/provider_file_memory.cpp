// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "base.hpp"

#include "cpp_helpers.hpp"
#include "test_helpers.h"
#ifndef _WIN32
#include "test_helpers_linux.h"
#endif

#include <umf/memory_provider.h>
#include <umf/providers/provider_file_memory.h>

using umf_test::test;

#define FILE_PATH ((char *)"tmp_file")
#define INVALID_PTR ((void *)0x01)

typedef enum purge_t {
    PURGE_NONE = 0,
    PURGE_LAZY = 1,
    PURGE_FORCE = 2,
} purge_t;

static const char *Native_error_str[] = {
    "success",                    // UMF_FILE_RESULT_SUCCESS
    "memory allocation failed",   // UMF_FILE_RESULT_ERROR_ALLOC_FAILED
    "memory deallocation failed", // UMF_FILE_RESULT_ERROR_FREE_FAILED
    "force purging failed",       // UMF_FILE_RESULT_ERROR_PURGE_FORCE_FAILED
};

// test helpers

static int compare_native_error_str(const char *message, int error) {
    const char *error_str = Native_error_str[error - UMF_FILE_RESULT_SUCCESS];
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

struct FileProviderParamsDefault
    : umf_test::test,
      ::testing::WithParamInterface<providerCreateExtParams> {
    void SetUp() override {
        test::SetUp();
        providerCreateExt(this->GetParam(), &provider);
        umf_result_t umf_result =
            umfMemoryProviderGetMinPageSize(provider.get(), NULL, &page_size);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

        page_plus_64 = page_size + 64;
    }

    void TearDown() override { test::TearDown(); }

    umf::provider_unique_handle_t provider;
    size_t page_size;
    size_t page_plus_64;
};

struct FileProviderParamsShared : FileProviderParamsDefault {};

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
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);
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

// Test checking if FSDAX was mapped with the MAP_SYNC flag:
TEST_F(test, test_if_mapped_with_MAP_SYNC) {
    umf_memory_provider_handle_t hProvider = nullptr;
    umf_result_t umf_result;

    char *path = getenv("UMF_TESTS_FSDAX_PATH");
    if (path == nullptr || path[0] == 0) {
        GTEST_SKIP() << "Test skipped, UMF_TESTS_FSDAX_PATH is not set";
    }

    auto params = umfFileMemoryProviderParamsDefault(path);
    params.visibility = UMF_MEM_MAP_SYNC;

    umf_result = umfMemoryProviderCreate(umfFileMemoryProviderOps(), &params,
                                         &hProvider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(hProvider, nullptr);

    char *buf;
    size_t size = 2 * 1024 * 1024; // 2MB
    umf_result = umfMemoryProviderAlloc(hProvider, size, 0, (void **)&buf);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(buf, nullptr);

    bool flag_found = is_mapped_with_MAP_SYNC(path, buf, size);

    umf_result = umfMemoryProviderFree(hProvider, buf, size);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    umfMemoryProviderDestroy(hProvider);

    // fail test if the "sf" flag was not found
    ASSERT_EQ(flag_found, true);
}

// positive tests using test_alloc_free_success

umf_file_memory_provider_params_t file_params_default =
    umfFileMemoryProviderParamsDefault(FILE_PATH);

umf_file_memory_provider_params_t get_file_params_shared(char *path) {
    umf_file_memory_provider_params_t file_params =
        umfFileMemoryProviderParamsDefault(path);
    file_params.visibility = UMF_MEM_MAP_SHARED;
    return file_params;
}

umf_file_memory_provider_params_t file_params_shared =
    get_file_params_shared(FILE_PATH);

INSTANTIATE_TEST_SUITE_P(fileProviderTest, FileProviderParamsDefault,
                         ::testing::Values(providerCreateExtParams{
                             umfFileMemoryProviderOps(),
                             &file_params_default}));

TEST_P(FileProviderParamsDefault, create_destroy) {}

TEST_P(FileProviderParamsDefault, two_allocations) {
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
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    umf_result = umfMemoryProviderFree(provider.get(), ptr2, size);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);
}

TEST_P(FileProviderParamsDefault, alloc_page64_align_0) {
    test_alloc_free_success(provider.get(), page_plus_64, 0, PURGE_NONE);
}

TEST_P(FileProviderParamsDefault, alloc_page64_align_page_div_2) {
    test_alloc_free_success(provider.get(), page_plus_64, page_size / 2,
                            PURGE_NONE);
}

TEST_P(FileProviderParamsDefault, purge_lazy) {
    test_alloc_free_success(provider.get(), page_plus_64, 0, PURGE_LAZY);
}

TEST_P(FileProviderParamsDefault, purge_force) {
    test_alloc_free_success(provider.get(), page_plus_64, 0, PURGE_FORCE);
}

// negative tests using test_alloc_failure

TEST_P(FileProviderParamsDefault, alloc_WRONG_SIZE) {
    test_alloc_failure(provider.get(), -1, 0, UMF_RESULT_ERROR_INVALID_ARGUMENT,
                       0);
}

TEST_P(FileProviderParamsDefault, alloc_page64_WRONG_ALIGNMENT_3_pages) {
    test_alloc_failure(provider.get(), page_plus_64, 3 * page_size,
                       UMF_RESULT_ERROR_INVALID_ALIGNMENT, 0);
}

TEST_P(FileProviderParamsDefault, alloc_3pages_WRONG_ALIGNMENT_3pages) {
    test_alloc_failure(provider.get(), 3 * page_size, 3 * page_size,
                       UMF_RESULT_ERROR_INVALID_ALIGNMENT, 0);
}

TEST_P(FileProviderParamsDefault,
       alloc_page64_align_page_minus_1_WRONG_ALIGNMENT_1) {
    test_alloc_failure(provider.get(), page_plus_64, page_size - 1,
                       UMF_RESULT_ERROR_INVALID_ALIGNMENT, 0);
}

TEST_P(FileProviderParamsDefault,
       alloc_page64_align_one_half_pages_WRONG_ALIGNMENT_2) {
    test_alloc_failure(provider.get(), page_plus_64,
                       page_size + (page_size / 2),
                       UMF_RESULT_ERROR_INVALID_ALIGNMENT, 0);
}

// negative IPC tests

TEST_P(FileProviderParamsDefault, get_ipc_handle_size_wrong_visibility) {
    size_t size;
    umf_result_t umf_result =
        umfMemoryProviderGetIPCHandleSize(provider.get(), &size);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_P(FileProviderParamsDefault, get_ipc_handle_wrong_visibility) {
    char providerIpcData;
    umf_result_t umf_result = umfMemoryProviderGetIPCHandle(
        provider.get(), INVALID_PTR, 1, &providerIpcData);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_P(FileProviderParamsDefault, put_ipc_handle_wrong_visibility) {
    char providerIpcData;
    umf_result_t umf_result =
        umfMemoryProviderPutIPCHandle(provider.get(), &providerIpcData);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_P(FileProviderParamsDefault, open_ipc_handle_wrong_visibility) {
    char providerIpcData;
    void *ptr;
    umf_result_t umf_result =
        umfMemoryProviderOpenIPCHandle(provider.get(), &providerIpcData, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_P(FileProviderParamsDefault, close_ipc_handle_wrong_visibility) {
    umf_result_t umf_result =
        umfMemoryProviderCloseIPCHandle(provider.get(), INVALID_PTR, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

// other positive tests

TEST_P(FileProviderParamsDefault, get_min_page_size) {
    size_t min_page_size;
    umf_result_t umf_result = umfMemoryProviderGetMinPageSize(
        provider.get(), nullptr, &min_page_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_LE(min_page_size, page_size);
}

TEST_P(FileProviderParamsDefault, get_recommended_page_size) {
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

TEST_P(FileProviderParamsDefault, get_name) {
    const char *name = umfMemoryProviderGetName(provider.get());
    ASSERT_STREQ(name, "FILE");
}

TEST_P(FileProviderParamsDefault, free_size_0_ptr_not_null) {
    umf_result_t umf_result =
        umfMemoryProviderFree(provider.get(), INVALID_PTR, 0);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);
}

TEST_P(FileProviderParamsDefault, free_NULL) {
    umf_result_t umf_result = umfMemoryProviderFree(provider.get(), nullptr, 0);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);
}

// other negative tests

TEST_F(test, create_empty_path) {
    umf_memory_provider_handle_t hProvider = nullptr;
    const char *path = "";
    auto wrong_params = umfFileMemoryProviderParamsDefault((char *)path);
    auto ret = umfMemoryProviderCreate(umfFileMemoryProviderOps(),
                                       &wrong_params, &hProvider);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(hProvider, nullptr);
}

TEST_P(FileProviderParamsDefault, free_INVALID_POINTER_SIZE_GT_0) {
    umf_result_t umf_result =
        umfMemoryProviderFree(provider.get(), INVALID_PTR, page_plus_64);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);
}

TEST_P(FileProviderParamsDefault, purge_lazy_INVALID_POINTER) {
    umf_result_t umf_result =
        umfMemoryProviderPurgeLazy(provider.get(), INVALID_PTR, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);
}

TEST_P(FileProviderParamsDefault, purge_force_INVALID_POINTER) {
    umf_result_t umf_result =
        umfMemoryProviderPurgeForce(provider.get(), INVALID_PTR, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC);

    verify_last_native_error(provider.get(),
                             UMF_FILE_RESULT_ERROR_PURGE_FORCE_FAILED);
}

// IPC tests

INSTANTIATE_TEST_SUITE_P(fileProviderTest, FileProviderParamsShared,
                         ::testing::Values(providerCreateExtParams{
                             umfFileMemoryProviderOps(), &file_params_shared}));

TEST_P(FileProviderParamsShared, IPC_base_success_test) {
    umf_result_t umf_result;
    void *ptr = nullptr;
    size_t size = page_size;
    void *ipc_handle = nullptr;
    size_t ipc_handle_size;
    void *new_ptr = nullptr;

    umf_result =
        umfMemoryProviderGetIPCHandleSize(provider.get(), &ipc_handle_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ipc_handle_size, 0);

    umf_result = umfMemoryProviderAlloc(provider.get(), size, page_size, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);
    memset(ptr, 0xFF, size);

    umf_result =
        umfMemoryProviderAlloc(provider.get(), ipc_handle_size, 0, &ipc_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ipc_handle, nullptr);
    memset(ipc_handle, 0x0, ipc_handle_size);

    umf_result =
        umfMemoryProviderGetIPCHandle(provider.get(), ptr, size, ipc_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result =
        umfMemoryProviderOpenIPCHandle(provider.get(), ipc_handle, &new_ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(new_ptr, nullptr);

    // it requires mapping with UMF_MEM_MAP_SHARED to work
    int ret = memcmp(ptr, new_ptr, size);
    ASSERT_EQ(ret, 0);

    umf_result = umfMemoryProviderFree(provider.get(), ptr, size);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);
}

TEST_P(FileProviderParamsShared, IPC_file_not_exist) {
    umf_result_t umf_result;
    void *ptr = nullptr;
    size_t size = page_size;
    void *ipc_handle = nullptr;
    size_t ipc_handle_size;
    void *new_ptr = nullptr;

    umf_result =
        umfMemoryProviderGetIPCHandleSize(provider.get(), &ipc_handle_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ipc_handle_size, 0);

    umf_result = umfMemoryProviderAlloc(provider.get(), size, page_size, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);
    memset(ptr, 0xFF, size);

    umf_result =
        umfMemoryProviderAlloc(provider.get(), ipc_handle_size, 0, &ipc_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ipc_handle, nullptr);
    memset(ipc_handle, 0x0, ipc_handle_size);

    umf_result =
        umfMemoryProviderGetIPCHandle(provider.get(), ptr, size, ipc_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    int ret = unlink(FILE_PATH);
    ASSERT_EQ(ret, 0);

    umf_result =
        umfMemoryProviderOpenIPCHandle(provider.get(), ipc_handle, &new_ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(new_ptr, nullptr);

    umf_result = umfMemoryProviderFree(provider.get(), ptr, size);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);
}
