// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#ifdef _WIN32
//workaround for std::numeric_limits on windows
#define NOMINMAX
#endif

#include <mutex>

#include <umf/providers/provider_level_zero.h>

#include "ipcFixtures.hpp"
#include "level_zero_helpers.h"
#include "pool.hpp"
#include "utils_load_library.h"

using umf_test::test;
using namespace umf_test;

struct LevelZeroProviderInit
    : public test,
      public ::testing::WithParamInterface<umf_usm_memory_type_t> {};

INSTANTIATE_TEST_SUITE_P(, LevelZeroProviderInit,
                         ::testing::Values(UMF_MEMORY_TYPE_HOST,
                                           UMF_MEMORY_TYPE_DEVICE,
                                           UMF_MEMORY_TYPE_SHARED));

TEST_P(LevelZeroProviderInit, FailNullContext) {
    umf_memory_provider_ops_t *ops = umfLevelZeroMemoryProviderOps();
    ASSERT_NE(ops, nullptr);

    auto memory_type = GetParam();

    level_zero_memory_provider_params_t params = {nullptr, nullptr, memory_type,
                                                  nullptr, 0};

    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t result = umfMemoryProviderCreate(ops, &params, &provider);
    ASSERT_EQ(result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_P(LevelZeroProviderInit, FailNullDevice) {
    if (GetParam() == UMF_MEMORY_TYPE_HOST) {
        GTEST_SKIP() << "Host memory does not require device handle";
    }

    umf_memory_provider_ops_t *ops = umfLevelZeroMemoryProviderOps();
    ASSERT_NE(ops, nullptr);

    auto memory_type = GetParam();
    auto params = create_level_zero_prov_params(memory_type);
    params.level_zero_device_handle = nullptr;

    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t result = umfMemoryProviderCreate(ops, &params, &provider);
    ASSERT_EQ(result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_F(test, FailNonNullDevice) {
    umf_memory_provider_ops_t *ops = umfLevelZeroMemoryProviderOps();
    ASSERT_NE(ops, nullptr);

    auto memory_type = UMF_MEMORY_TYPE_HOST;

    // prepare params for device to get non-null device handle
    auto params = create_level_zero_prov_params(UMF_MEMORY_TYPE_DEVICE);
    params.memory_type = memory_type;

    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t result = umfMemoryProviderCreate(ops, &params, &provider);
    ASSERT_EQ(result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_F(test, FailMismatchedResidentHandlesCount) {
    umf_memory_provider_ops_t *ops = umfLevelZeroMemoryProviderOps();
    ASSERT_NE(ops, nullptr);

    auto memory_type = UMF_MEMORY_TYPE_DEVICE;

    auto params = create_level_zero_prov_params(memory_type);
    params.resident_device_count = 99;

    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t result = umfMemoryProviderCreate(ops, &params, &provider);
    ASSERT_EQ(result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_F(test, FailMismatchedResidentHandlesPtr) {
    umf_memory_provider_ops_t *ops = umfLevelZeroMemoryProviderOps();
    ASSERT_NE(ops, nullptr);

    auto memory_type = UMF_MEMORY_TYPE_DEVICE;

    auto params = create_level_zero_prov_params(memory_type);
    params.resident_device_handles = &params.level_zero_device_handle;

    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t result = umfMemoryProviderCreate(ops, &params, &provider);
    ASSERT_EQ(result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

class LevelZeroMemoryAccessor : public MemoryAccessor {
  public:
    LevelZeroMemoryAccessor(ze_context_handle_t hContext,
                            ze_device_handle_t hDevice)
        : hDevice_(hDevice), hContext_(hContext) {}
    void fill(void *ptr, size_t size, const void *pattern,
              size_t pattern_size) {
        ASSERT_NE(ptr, nullptr);

        int ret = level_zero_fill(hContext_, hDevice_, ptr, size, pattern,
                                  pattern_size);
        ASSERT_EQ(ret, 0);
    }

    void copy(void *dst_ptr, void *src_ptr, size_t size) {
        ASSERT_NE(dst_ptr, nullptr);
        ASSERT_NE(src_ptr, nullptr);

        int ret = level_zero_copy(hContext_, hDevice_, dst_ptr, src_ptr, size);
        ASSERT_EQ(ret, 0);
    }

  private:
    ze_device_handle_t hDevice_;
    ze_context_handle_t hContext_;
};

using LevelZeroProviderTestParams =
    std::tuple<level_zero_memory_provider_params_t, MemoryAccessor *>;

struct umfLevelZeroProviderTest
    : umf_test::test,
      ::testing::WithParamInterface<LevelZeroProviderTestParams> {

    void SetUp() override {
        test::SetUp();

        auto [l0_params, accessor] = this->GetParam();
        params = l0_params;
        memAccessor = accessor;
        hContext = (ze_context_handle_t)params.level_zero_context_handle;

        ASSERT_NE(hContext, nullptr);

        switch (params.memory_type) {
        case UMF_MEMORY_TYPE_DEVICE:
            zeMemoryTypeExpected = ZE_MEMORY_TYPE_DEVICE;
            break;
        case UMF_MEMORY_TYPE_SHARED:
            zeMemoryTypeExpected = ZE_MEMORY_TYPE_SHARED;
            break;
        case UMF_MEMORY_TYPE_HOST:
            zeMemoryTypeExpected = ZE_MEMORY_TYPE_HOST;
            break;
        case UMF_MEMORY_TYPE_UNKNOWN:
            zeMemoryTypeExpected = ZE_MEMORY_TYPE_UNKNOWN;
            break;
        }

        ASSERT_NE(zeMemoryTypeExpected, ZE_MEMORY_TYPE_UNKNOWN);
    }

    void TearDown() override { test::TearDown(); }

    level_zero_memory_provider_params_t params;
    MemoryAccessor *memAccessor = nullptr;
    ze_context_handle_t hContext = nullptr;
    ze_memory_type_t zeMemoryTypeExpected = ZE_MEMORY_TYPE_UNKNOWN;
};

GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfLevelZeroProviderTest);

TEST_P(umfLevelZeroProviderTest, basic) {
    const size_t size = 1024 * 8;
    const uint32_t pattern = 0xAB;

    // create Level Zero provider
    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t umf_result = umfMemoryProviderCreate(
        umfLevelZeroMemoryProviderOps(), &params, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    void *ptr = nullptr;
    umf_result = umfMemoryProviderAlloc(provider, size, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    // use the allocated memory - fill it with a 0xAB pattern
    memAccessor->fill(ptr, size, &pattern, sizeof(pattern));

    ze_memory_type_t zeMemoryTypeActual = get_mem_type(hContext, ptr);
    ASSERT_EQ(zeMemoryTypeActual, zeMemoryTypeExpected);

    // check if the pattern was successfully applied
    uint32_t *hostMemory = (uint32_t *)calloc(1, size);
    memAccessor->copy(hostMemory, ptr, size);
    for (size_t i = 0; i < size / sizeof(int); i++) {
        ASSERT_EQ(hostMemory[i], pattern);
    }
    free(hostMemory);

    umf_result = umfMemoryProviderFree(provider, ptr, size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umfMemoryProviderDestroy(provider);
}

TEST_P(umfLevelZeroProviderTest, getPageSize) {
    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t umf_result = umfMemoryProviderCreate(
        umfLevelZeroMemoryProviderOps(), &params, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    size_t recommendedPageSize = 0;
    umf_result = umfMemoryProviderGetRecommendedPageSize(provider, 0,
                                                         &recommendedPageSize);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_GE(recommendedPageSize, 0);

    size_t minPageSize = 0;
    umf_result =
        umfMemoryProviderGetMinPageSize(provider, nullptr, &minPageSize);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_GE(minPageSize, 0);

    ASSERT_GE(recommendedPageSize, minPageSize);

    umfMemoryProviderDestroy(provider);
}

TEST_P(umfLevelZeroProviderTest, getName) {
    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t umf_result = umfMemoryProviderCreate(
        umfLevelZeroMemoryProviderOps(), &params, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    const char *name = umfMemoryProviderGetName(provider);
    ASSERT_STREQ(name, "LEVEL_ZERO");

    umfMemoryProviderDestroy(provider);
}

TEST_P(umfLevelZeroProviderTest, allocInvalidSize) {
    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t umf_result = umfMemoryProviderCreate(
        umfLevelZeroMemoryProviderOps(), &params, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    // try to alloc (int)-1
    void *ptr = nullptr;
    umf_result = umfMemoryProviderAlloc(provider, -1, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC);
    const char *message;
    int32_t error;
    umfMemoryProviderGetLastNativeError(provider, &message, &error);
    ASSERT_EQ(error, ZE_RESULT_ERROR_UNSUPPORTED_SIZE);

    // in case of size == 0 we should got INVALID_ARGUMENT error
    // NOTE: this is invalid only for the DEVICE or SHARED allocations
    if (params.memory_type != UMF_MEMORY_TYPE_HOST) {
        umf_result = umfMemoryProviderAlloc(provider, 0, 0, &ptr);
        ASSERT_EQ(umf_result, UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC);
        umfMemoryProviderGetLastNativeError(provider, &message, &error);
        ASSERT_EQ(error, ZE_RESULT_ERROR_UNSUPPORTED_SIZE);
    }

    umfMemoryProviderDestroy(provider);
}

TEST_P(umfLevelZeroProviderTest, providerCreateInvalidArgs) {
    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t umf_result = umfMemoryProviderCreate(
        umfLevelZeroMemoryProviderOps(), nullptr, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umf_result = umfMemoryProviderCreate(nullptr, &params, nullptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_P(umfLevelZeroProviderTest, getPageSizeInvalidArgs) {
    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t umf_result = umfMemoryProviderCreate(
        umfLevelZeroMemoryProviderOps(), &params, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    umf_result = umfMemoryProviderGetMinPageSize(provider, nullptr, nullptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umf_result = umfMemoryProviderGetRecommendedPageSize(provider, 0, nullptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umfMemoryProviderDestroy(provider);
}

// TODO add tests that mixes Level Zero Memory Provider and Disjoint Pool

level_zero_memory_provider_params_t l0Params_device_memory =
    create_level_zero_prov_params(UMF_MEMORY_TYPE_DEVICE);
level_zero_memory_provider_params_t l0Params_shared_memory =
    create_level_zero_prov_params(UMF_MEMORY_TYPE_SHARED);
level_zero_memory_provider_params_t l0Params_host_memory =
    create_level_zero_prov_params(UMF_MEMORY_TYPE_HOST);

LevelZeroMemoryAccessor l0Accessor(
    (ze_context_handle_t)l0Params_device_memory.level_zero_context_handle,
    (ze_device_handle_t)l0Params_device_memory.level_zero_device_handle);

HostMemoryAccessor hostAccessor;

INSTANTIATE_TEST_SUITE_P(
    umfLevelZeroProviderTestSuite, umfLevelZeroProviderTest,
    ::testing::Values(
        LevelZeroProviderTestParams{l0Params_device_memory, &l0Accessor},
        LevelZeroProviderTestParams{l0Params_shared_memory, &hostAccessor},
        LevelZeroProviderTestParams{l0Params_host_memory, &hostAccessor}));

// TODO: it looks like there is some problem with IPC implementation in Level
// Zero on windows. Issue: #494
#ifdef _WIN32
GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfIpcTest);
#else
INSTANTIATE_TEST_SUITE_P(umfLevelZeroProviderTestSuite, umfIpcTest,
                         ::testing::Values(ipcTestParams{
                             umfProxyPoolOps(), nullptr,
                             umfLevelZeroMemoryProviderOps(),
                             &l0Params_device_memory, &l0Accessor}));
#endif
