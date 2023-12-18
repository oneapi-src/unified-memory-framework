// Copyright (C) 2023 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "base.hpp"

#include "provider_os_memory_internal.h"
#include "umf/providers/provider_os_memory.h"
#include <umf/memory_provider.h>

using umf_test::test;

#define SIZE_4K (4096)

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
    "success",                            // UMF_OS_RESULT_SUCCESS
    "wrong alignment (not a power of 2)", // UMF_OS_RESULT_ERROR_WRONG_ALIGNMENT
    "memory allocation failed",           // UMF_OS_RESULT_ERROR_ALLOC_FAILED
    "allocated address is not aligned", // UMF_OS_RESULT_ERROR_ADDRESS_NOT_ALIGNED
    "binding memory to NUMA node failed", // UMF_OS_RESULT_ERROR_BIND_FAILED
    "memory deallocation failed",         // UMF_OS_RESULT_ERROR_FREE_FAILED
    "lazy purging failed",  // UMF_OS_RESULT_ERROR_PURGE_LAZY_FAILED
    "force purging failed", // UMF_OS_RESULT_ERROR_PURGE_FORCE_FAILED
};

static int compare_native_error_str(const char *message, int error) {
    const char *error_str = Native_error_str[error - UMF_OS_RESULT_SUCCESS];
    size_t len = strlen(error_str);
    return strncmp(message, error_str, len);
}

TEST_F(test, provider_os_memory_create_destroy) {
    umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = nullptr;
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;

    umf_result = umfMemoryProviderCreate(&UMF_OS_MEMORY_PROVIDER_OPS,
                                         &os_memory_provider_params,
                                         &os_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(os_memory_provider, nullptr);

    umfMemoryProviderDestroy(os_memory_provider);
}

TEST_F(test, provider_os_memory_create_UMF_NUMA_MODE_NOT_SUPPORTED) {
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

TEST_F(test, provider_os_memory_create_MBIND_FAILED) {
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

TEST_F(test, provider_os_memory_alloc_free_4k_alignment_0) {
    umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = nullptr;
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;

    umf_result = umfMemoryProviderCreate(&UMF_OS_MEMORY_PROVIDER_OPS,
                                         &os_memory_provider_params,
                                         &os_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(os_memory_provider, nullptr);

    void *ptr = nullptr;
    size_t size = SIZE_4K;
    size_t alignment = 0;
    umf_result =
        umfMemoryProviderAlloc(os_memory_provider, size, alignment, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    memset(ptr, 0xFF, size);

    umf_result = umfMemoryProviderFree(os_memory_provider, ptr, size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umfMemoryProviderDestroy(os_memory_provider);
}

TEST_F(test, provider_os_memory_alloc_free_2k_alignment_2k) {
    umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = nullptr;
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;

    umf_result = umfMemoryProviderCreate(&UMF_OS_MEMORY_PROVIDER_OPS,
                                         &os_memory_provider_params,
                                         &os_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(os_memory_provider, nullptr);

    void *ptr = nullptr;
    size_t size = SIZE_4K / 2;
    size_t alignment = SIZE_4K / 2;
    umf_result =
        umfMemoryProviderAlloc(os_memory_provider, size, alignment, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    memset(ptr, 0xFF, size);

    umf_result = umfMemoryProviderFree(os_memory_provider, ptr, size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umfMemoryProviderDestroy(os_memory_provider);
}

TEST_F(test, provider_os_memory_alloc_free_8k_alignment_8k) {
    umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = nullptr;
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;

    umf_result = umfMemoryProviderCreate(&UMF_OS_MEMORY_PROVIDER_OPS,
                                         &os_memory_provider_params,
                                         &os_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(os_memory_provider, nullptr);

    void *ptr = nullptr;
    size_t size = 2 * SIZE_4K;
    size_t alignment = 2 * SIZE_4K;
    umf_result =
        umfMemoryProviderAlloc(os_memory_provider, size, alignment, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    memset(ptr, 0xFF, size);

    umf_result = umfMemoryProviderFree(os_memory_provider, ptr, size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umfMemoryProviderDestroy(os_memory_provider);
}

TEST_F(test, provider_os_memory_alloc_WRONG_ALIGNMENT) {
    umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = nullptr;
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;

    umf_result = umfMemoryProviderCreate(&UMF_OS_MEMORY_PROVIDER_OPS,
                                         &os_memory_provider_params,
                                         &os_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(os_memory_provider, nullptr);

    void *ptr = nullptr;
    size_t size = SIZE_4K;
    size_t alignment = SIZE_4K - 1; // wrong alignment
    umf_result =
        umfMemoryProviderAlloc(os_memory_provider, size, alignment, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC);
    ASSERT_EQ(ptr, nullptr);

    const char *message;
    int32_t error;
    umfMemoryProviderGetLastNativeError(os_memory_provider, &message, &error);
    ASSERT_EQ(error, UMF_OS_RESULT_ERROR_WRONG_ALIGNMENT);
    ASSERT_EQ(compare_native_error_str(message, error), 0);

    umfMemoryProviderDestroy(os_memory_provider);
}

TEST_F(test, provider_os_memory_alloc_MMAP_FAILED) {
    umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = nullptr;
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;

    umf_result = umfMemoryProviderCreate(&UMF_OS_MEMORY_PROVIDER_OPS,
                                         &os_memory_provider_params,
                                         &os_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(os_memory_provider, nullptr);

    void *ptr = nullptr;
    size_t size = -1; // wrong size
    size_t alignment = 0;
    umf_result =
        umfMemoryProviderAlloc(os_memory_provider, size, alignment, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC);
    ASSERT_EQ(ptr, nullptr);

    const char *message;
    int32_t error;
    umfMemoryProviderGetLastNativeError(os_memory_provider, &message, &error);
    ASSERT_EQ(error, UMF_OS_RESULT_ERROR_ALLOC_FAILED);
    ASSERT_EQ(compare_native_error_str(message, error), 0);

    umfMemoryProviderDestroy(os_memory_provider);
}

TEST_F(test, provider_os_memory_free_MUNMAP_FAILED) {
    umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = nullptr;
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;

    umf_result = umfMemoryProviderCreate(&UMF_OS_MEMORY_PROVIDER_OPS,
                                         &os_memory_provider_params,
                                         &os_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(os_memory_provider, nullptr);

    umf_result = umfMemoryProviderFree(os_memory_provider, (void *)0x01, 0);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC);

    const char *message;
    int32_t error;
    umfMemoryProviderGetLastNativeError(os_memory_provider, &message, &error);
    ASSERT_EQ(error, UMF_OS_RESULT_ERROR_FREE_FAILED);
    ASSERT_EQ(compare_native_error_str(message, error), 0);

    umfMemoryProviderDestroy(os_memory_provider);
}

TEST_F(test, provider_os_memory_get_min_page_size) {
    umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = nullptr;
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;

    umf_result = umfMemoryProviderCreate(&UMF_OS_MEMORY_PROVIDER_OPS,
                                         &os_memory_provider_params,
                                         &os_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(os_memory_provider, nullptr);

    size_t min_page_size;
    umf_result = umfMemoryProviderGetMinPageSize(os_memory_provider, nullptr,
                                                 &min_page_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_LE(min_page_size, SIZE_4K);

    umfMemoryProviderDestroy(os_memory_provider);
}

TEST_F(test, provider_os_memory_get_recommended_page_size) {
    umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = nullptr;
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;

    umf_result = umfMemoryProviderCreate(&UMF_OS_MEMORY_PROVIDER_OPS,
                                         &os_memory_provider_params,
                                         &os_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(os_memory_provider, nullptr);

    size_t min_page_size;
    umf_result = umfMemoryProviderGetMinPageSize(os_memory_provider, nullptr,
                                                 &min_page_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_LE(min_page_size, SIZE_4K);

    size_t recommended_page_size;
    umf_result = umfMemoryProviderGetRecommendedPageSize(
        os_memory_provider, 0, &recommended_page_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_GE(recommended_page_size, min_page_size);

    umfMemoryProviderDestroy(os_memory_provider);
}

TEST_F(test, provider_os_memory_purge_lazy) {
    umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = nullptr;
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;

    umf_result = umfMemoryProviderCreate(&UMF_OS_MEMORY_PROVIDER_OPS,
                                         &os_memory_provider_params,
                                         &os_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(os_memory_provider, nullptr);

    void *ptr = nullptr;
    size_t size = SIZE_4K;
    size_t alignment = 0;
    umf_result =
        umfMemoryProviderAlloc(os_memory_provider, size, alignment, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    memset(ptr, 0xFF, size);

    umf_result = umfMemoryProviderPurgeLazy(os_memory_provider, ptr, size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result = umfMemoryProviderFree(os_memory_provider, ptr, size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umfMemoryProviderDestroy(os_memory_provider);
}

TEST_F(test, provider_os_memory_purge_lazy_MADVISE_FREE_FAILED) {
    umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = nullptr;
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;

    umf_result = umfMemoryProviderCreate(&UMF_OS_MEMORY_PROVIDER_OPS,
                                         &os_memory_provider_params,
                                         &os_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(os_memory_provider, nullptr);

    umf_result =
        umfMemoryProviderPurgeLazy(os_memory_provider, (void *)0x01, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC);

    const char *message;
    int32_t error;
    umfMemoryProviderGetLastNativeError(os_memory_provider, &message, &error);
    ASSERT_EQ(error, UMF_OS_RESULT_ERROR_PURGE_LAZY_FAILED);
    ASSERT_EQ(compare_native_error_str(message, error), 0);

    umfMemoryProviderDestroy(os_memory_provider);
}

TEST_F(test, provider_os_memory_purge_force) {
    umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = nullptr;
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;

    umf_result = umfMemoryProviderCreate(&UMF_OS_MEMORY_PROVIDER_OPS,
                                         &os_memory_provider_params,
                                         &os_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(os_memory_provider, nullptr);

    void *ptr = nullptr;
    size_t size = SIZE_4K;
    size_t alignment = 0;
    umf_result =
        umfMemoryProviderAlloc(os_memory_provider, size, alignment, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    memset(ptr, 0xFF, size);

    umf_result = umfMemoryProviderPurgeForce(os_memory_provider, ptr, size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result = umfMemoryProviderFree(os_memory_provider, ptr, size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umfMemoryProviderDestroy(os_memory_provider);
}

TEST_F(test, provider_os_memory_purge_force_MADVISE_DONTNEED_FAILED) {
    umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = nullptr;
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;

    umf_result = umfMemoryProviderCreate(&UMF_OS_MEMORY_PROVIDER_OPS,
                                         &os_memory_provider_params,
                                         &os_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(os_memory_provider, nullptr);

    umf_result =
        umfMemoryProviderPurgeForce(os_memory_provider, (void *)0x01, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC);

    const char *message;
    int32_t error;
    umfMemoryProviderGetLastNativeError(os_memory_provider, &message, &error);
    ASSERT_EQ(error, UMF_OS_RESULT_ERROR_PURGE_FORCE_FAILED);
    ASSERT_EQ(compare_native_error_str(message, error), 0);

    umfMemoryProviderDestroy(os_memory_provider);
}

TEST_F(test, provider_os_memory_get_name) {
    umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = nullptr;
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;

    umf_result = umfMemoryProviderCreate(&UMF_OS_MEMORY_PROVIDER_OPS,
                                         &os_memory_provider_params,
                                         &os_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(os_memory_provider, nullptr);

    const char *name = umfMemoryProviderGetName(os_memory_provider);
    ASSERT_STREQ(name, "OS");

    umfMemoryProviderDestroy(os_memory_provider);
}
