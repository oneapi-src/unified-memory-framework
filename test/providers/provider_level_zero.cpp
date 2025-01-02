// Copyright (C) 2024-2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#ifdef _WIN32
//workaround for std::numeric_limits on windows
#define NOMINMAX
#endif

#include <mutex>

#include <umf/providers/provider_level_zero.h>

#include "ipcFixtures.hpp"
#include "pool.hpp"
#include "utils_level_zero.h"
#include "utils_load_library.h"

using umf_test::test;
using namespace umf_test;

class LevelZeroTestHelper {
  public:
    LevelZeroTestHelper();

    ~LevelZeroTestHelper() {
        if (hContext_) {
            utils_ze_destroy_context(hContext_);
        }
    }

    ze_context_handle_t get_test_context() const { return hContext_; }

    ze_device_handle_t get_test_device() const { return hDevice_; }

  private:
    ze_driver_handle_t hDriver_ = nullptr;
    ze_context_handle_t hContext_ = nullptr;
    ze_device_handle_t hDevice_ = nullptr;
};

LevelZeroTestHelper::LevelZeroTestHelper() {
    uint32_t driver_idx = 0;

    int ret = utils_ze_find_driver_with_gpu(&driver_idx, &hDriver_);
    if (ret != 0 || hDriver_ == NULL) {
        fprintf(stderr, "utils_ze_find_driver_with_gpu() failed!\n");
        return;
    }

    ret = utils_ze_find_gpu_device(hDriver_, &hDevice_);
    if (ret != 0 || hDevice_ == NULL) {
        fprintf(stderr, "utils_ze_find_gpu_device() failed!\n");
        return;
    }

    ret = utils_ze_create_context(hDriver_, &hContext_);
    if (ret != 0) {
        fprintf(stderr, "utils_ze_create_context() failed!\n");
        return;
    }
}

umf_level_zero_memory_provider_params_handle_t
create_level_zero_prov_params(ze_context_handle_t context,
                              ze_device_handle_t device,
                              umf_usm_memory_type_t memory_type) {
    umf_level_zero_memory_provider_params_handle_t params = nullptr;

    umf_result_t res = umfLevelZeroMemoryProviderParamsCreate(&params);
    if (res != UMF_RESULT_SUCCESS) {
        return nullptr;
    }

    res = umfLevelZeroMemoryProviderParamsSetContext(params, context);
    if (res != UMF_RESULT_SUCCESS) {
        umfLevelZeroMemoryProviderParamsDestroy(params);
        return nullptr;
    }

    res = umfLevelZeroMemoryProviderParamsSetDevice(params, device);
    if (res != UMF_RESULT_SUCCESS) {
        umfLevelZeroMemoryProviderParamsDestroy(params);
        return nullptr;
    }

    res = umfLevelZeroMemoryProviderParamsSetMemoryType(params, memory_type);
    if (res != UMF_RESULT_SUCCESS) {
        umfLevelZeroMemoryProviderParamsDestroy(params);
        return nullptr;
    }

    return params;
}

struct LevelZeroProviderInit
    : public test,
      public ::testing::WithParamInterface<umf_usm_memory_type_t> {};

INSTANTIATE_TEST_SUITE_P(, LevelZeroProviderInit,
                         ::testing::Values(UMF_MEMORY_TYPE_HOST,
                                           UMF_MEMORY_TYPE_DEVICE,
                                           UMF_MEMORY_TYPE_SHARED));

LevelZeroTestHelper l0TestHelper;

TEST_P(LevelZeroProviderInit, FailNullContext) {
    umf_memory_provider_ops_t *ops = umfLevelZeroMemoryProviderOps();
    ASSERT_NE(ops, nullptr);

    auto memory_type = GetParam();

    umf_level_zero_memory_provider_params_handle_t hParams = nullptr;
    umf_result_t result = umfLevelZeroMemoryProviderParamsCreate(&hParams);
    ASSERT_EQ(result, UMF_RESULT_SUCCESS);
    result =
        umfLevelZeroMemoryProviderParamsSetMemoryType(hParams, memory_type);
    ASSERT_EQ(result, UMF_RESULT_SUCCESS);
    result = umfLevelZeroMemoryProviderParamsSetDevice(
        hParams, l0TestHelper.get_test_device());
    ASSERT_EQ(result, UMF_RESULT_SUCCESS);

    result = umfLevelZeroMemoryProviderParamsSetContext(hParams, nullptr);
    ASSERT_EQ(result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umf_memory_provider_handle_t provider = nullptr;
    result = umfMemoryProviderCreate(ops, hParams, &provider);
    ASSERT_EQ(result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umfLevelZeroMemoryProviderParamsDestroy(hParams);
}

TEST_P(LevelZeroProviderInit, FailNullDevice) {
    if (GetParam() == UMF_MEMORY_TYPE_HOST) {
        GTEST_SKIP() << "Host memory does not require device handle";
    }

    umf_memory_provider_ops_t *ops = umfLevelZeroMemoryProviderOps();
    ASSERT_NE(ops, nullptr);

    auto memory_type = GetParam();
    umf_level_zero_memory_provider_params_handle_t hParams = nullptr;
    umf_result_t result = umfLevelZeroMemoryProviderParamsCreate(&hParams);
    ASSERT_EQ(result, UMF_RESULT_SUCCESS);
    result =
        umfLevelZeroMemoryProviderParamsSetMemoryType(hParams, memory_type);
    ASSERT_EQ(result, UMF_RESULT_SUCCESS);
    result = umfLevelZeroMemoryProviderParamsSetContext(
        hParams, l0TestHelper.get_test_context());
    ASSERT_EQ(result, UMF_RESULT_SUCCESS);

    umf_memory_provider_handle_t provider = nullptr;
    result = umfMemoryProviderCreate(ops, hParams, &provider);
    ASSERT_EQ(result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umfLevelZeroMemoryProviderParamsDestroy(hParams);
}

TEST_F(test, FailNonNullDevice) {
    umf_memory_provider_ops_t *ops = umfLevelZeroMemoryProviderOps();
    ASSERT_NE(ops, nullptr);

    auto memory_type = UMF_MEMORY_TYPE_HOST;

    umf_level_zero_memory_provider_params_handle_t hParams = nullptr;
    umf_result_t result = umfLevelZeroMemoryProviderParamsCreate(&hParams);
    ASSERT_EQ(result, UMF_RESULT_SUCCESS);
    result =
        umfLevelZeroMemoryProviderParamsSetMemoryType(hParams, memory_type);
    ASSERT_EQ(result, UMF_RESULT_SUCCESS);
    result = umfLevelZeroMemoryProviderParamsSetContext(
        hParams, l0TestHelper.get_test_context());
    ASSERT_EQ(result, UMF_RESULT_SUCCESS);
    result = umfLevelZeroMemoryProviderParamsSetDevice(
        hParams, l0TestHelper.get_test_device());
    ASSERT_EQ(result, UMF_RESULT_SUCCESS);

    umf_memory_provider_handle_t provider = nullptr;
    result = umfMemoryProviderCreate(ops, hParams, &provider);
    ASSERT_EQ(result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umfLevelZeroMemoryProviderParamsDestroy(hParams);
}

TEST_F(test, FailMismatchedResidentHandlesCount) {
    umf_memory_provider_ops_t *ops = umfLevelZeroMemoryProviderOps();
    ASSERT_NE(ops, nullptr);

    umf_level_zero_memory_provider_params_handle_t hParams = nullptr;
    umf_result_t result = umfLevelZeroMemoryProviderParamsCreate(&hParams);
    ASSERT_EQ(result, UMF_RESULT_SUCCESS);

    result = umfLevelZeroMemoryProviderParamsSetResidentDevices(hParams,
                                                                nullptr, 99);
    ASSERT_EQ(result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umfLevelZeroMemoryProviderParamsDestroy(hParams);
}

class LevelZeroMemoryAccessor : public MemoryAccessor {
  public:
    LevelZeroMemoryAccessor(ze_context_handle_t hContext,
                            ze_device_handle_t hDevice)
        : hDevice_(hDevice), hContext_(hContext) {}
    void fill(void *ptr, size_t size, const void *pattern,
              size_t pattern_size) {
        ASSERT_NE(ptr, nullptr);

        int ret = utils_ze_level_zero_fill(hContext_, hDevice_, ptr, size,
                                           pattern, pattern_size);
        ASSERT_EQ(ret, 0);
    }

    void copy(void *dst_ptr, void *src_ptr, size_t size) {
        ASSERT_NE(dst_ptr, nullptr);
        ASSERT_NE(src_ptr, nullptr);

        int ret = utils_ze_level_zero_copy(hContext_, hDevice_, dst_ptr,
                                           src_ptr, size);
        ASSERT_EQ(ret, 0);
    }

  private:
    ze_device_handle_t hDevice_;
    ze_context_handle_t hContext_;
};

typedef void *(*pfnProviderParamsCreate)();
typedef umf_result_t (*pfnProviderParamsDestroy)(void *);

using LevelZeroProviderTestParams =
    std::tuple<pfnProviderParamsCreate, pfnProviderParamsDestroy,
               ze_context_handle_t, umf_usm_memory_type_t, MemoryAccessor *>;

struct umfLevelZeroProviderTest
    : umf_test::test,
      ::testing::WithParamInterface<LevelZeroProviderTestParams> {

    void SetUp() override {
        test::SetUp();

        auto [params_create, params_destroy, ze_context, memory_type,
              accessor] = this->GetParam();

        params = nullptr;
        if (params_create) {
            params =
                (umf_level_zero_memory_provider_params_handle_t)params_create();
        }
        paramsDestroy = params_destroy;

        memAccessor = accessor;
        hContext = ze_context;

        ASSERT_NE(hContext, nullptr);

        switch (memory_type) {
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

    void TearDown() override {
        if (paramsDestroy) {
            paramsDestroy(params);
        }

        test::TearDown();
    }

    umf_level_zero_memory_provider_params_handle_t params;
    pfnProviderParamsDestroy paramsDestroy = nullptr;

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
        umfLevelZeroMemoryProviderOps(), params, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    void *ptr = nullptr;
    umf_result = umfMemoryProviderAlloc(provider, size, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    // use the allocated memory - fill it with a 0xAB pattern
    memAccessor->fill(ptr, size, &pattern, sizeof(pattern));

    ze_memory_type_t zeMemoryTypeActual = utils_ze_get_mem_type(hContext, ptr);
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
        umfLevelZeroMemoryProviderOps(), params, &provider);
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

    void *ptr;
    umf_result = umfMemoryProviderAlloc(provider, 1, 0, &ptr);

    size_t actualPageSize = 0;
    umf_result =
        umfMemoryProviderGetMinPageSize(provider, ptr, &actualPageSize);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_GE(actualPageSize, minPageSize);

    umf_result = umfMemoryProviderFree(provider, ptr, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umfMemoryProviderDestroy(provider);
}

TEST_P(umfLevelZeroProviderTest, getName) {
    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t umf_result = umfMemoryProviderCreate(
        umfLevelZeroMemoryProviderOps(), params, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    const char *name = umfMemoryProviderGetName(provider);
    ASSERT_STREQ(name, "LEVEL_ZERO");

    umfMemoryProviderDestroy(provider);
}

TEST_P(umfLevelZeroProviderTest, allocInvalidSize) {
    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t umf_result = umfMemoryProviderCreate(
        umfLevelZeroMemoryProviderOps(), params, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    void *ptr = nullptr;
    umf_result = umfMemoryProviderAlloc(
        provider, std::numeric_limits<size_t>::max(), 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC);
    const char *message;
    int32_t error;
    umfMemoryProviderGetLastNativeError(provider, &message, &error);
    ASSERT_EQ(error, ZE_RESULT_ERROR_UNSUPPORTED_SIZE);

    umfMemoryProviderDestroy(provider);
}

TEST_P(umfLevelZeroProviderTest, providerCreateInvalidArgs) {
    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t umf_result = umfMemoryProviderCreate(
        umfLevelZeroMemoryProviderOps(), nullptr, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umf_result = umfMemoryProviderCreate(nullptr, params, nullptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_P(umfLevelZeroProviderTest, getPageSizeInvalidArgs) {
    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t umf_result = umfMemoryProviderCreate(
        umfLevelZeroMemoryProviderOps(), params, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    umf_result = umfMemoryProviderGetMinPageSize(provider, nullptr, nullptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umf_result = umfMemoryProviderGetRecommendedPageSize(provider, 0, nullptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umfMemoryProviderDestroy(provider);
}

TEST_P(umfLevelZeroProviderTest, levelZeroProviderNullParams) {
    umf_result_t res = umfLevelZeroMemoryProviderParamsCreate(nullptr);
    EXPECT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfLevelZeroMemoryProviderParamsSetContext(nullptr, hContext);
    EXPECT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfLevelZeroMemoryProviderParamsSetDevice(nullptr, nullptr);
    EXPECT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfLevelZeroMemoryProviderParamsSetMemoryType(nullptr,
                                                        UMF_MEMORY_TYPE_DEVICE);
    EXPECT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfLevelZeroMemoryProviderParamsSetDeviceOrdinal(nullptr, 0);
    EXPECT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_P(umfLevelZeroProviderTest, setDeviceOrdinalValid) {
    int64_t numProps =
        utils_ze_get_num_memory_properties(l0TestHelper.get_test_device());
    ASSERT_GE(numProps, 0);

    for (uint32_t ordinal = 0; ordinal < static_cast<uint32_t>(numProps);
         ordinal++) {
        umf_memory_provider_handle_t provider = nullptr;
        umf_result_t res =
            umfLevelZeroMemoryProviderParamsSetDeviceOrdinal(params, ordinal);
        EXPECT_EQ(res, UMF_RESULT_SUCCESS);

        res = umfMemoryProviderCreate(umfLevelZeroMemoryProviderOps(), params,
                                      &provider);
        ASSERT_EQ(res, UMF_RESULT_SUCCESS);
        ASSERT_NE(provider, nullptr);

        size_t size = 1024;
        void *ptr = nullptr;
        res = umfMemoryProviderAlloc(provider, size, 0, &ptr);
        ASSERT_EQ(res, UMF_RESULT_SUCCESS);
        ASSERT_NE(ptr, nullptr);

        res = umfMemoryProviderFree(provider, ptr, size);
        ASSERT_EQ(res, UMF_RESULT_SUCCESS);

        umfMemoryProviderDestroy(provider);
    }
}

// TODO add tests that mixes Level Zero Memory Provider and Disjoint Pool

void *createL0ParamsDeviceMemory() {
    return create_level_zero_prov_params(l0TestHelper.get_test_context(),
                                         l0TestHelper.get_test_device(),
                                         UMF_MEMORY_TYPE_DEVICE);
}

void *createL0ParamsSharedMemory() {
    return create_level_zero_prov_params(l0TestHelper.get_test_context(),
                                         l0TestHelper.get_test_device(),
                                         UMF_MEMORY_TYPE_SHARED);
}

void *createL0ParamsHostMemory() {
    return create_level_zero_prov_params(l0TestHelper.get_test_context(),
                                         nullptr, UMF_MEMORY_TYPE_HOST);
}

umf_result_t destroyL0Params(void *params) {
    return umfLevelZeroMemoryProviderParamsDestroy(
        static_cast<umf_level_zero_memory_provider_params_handle_t>(params));
}

LevelZeroMemoryAccessor
    l0Accessor((ze_context_handle_t)l0TestHelper.get_test_context(),
               (ze_device_handle_t)l0TestHelper.get_test_device());

HostMemoryAccessor hostAccessor;

INSTANTIATE_TEST_SUITE_P(
    umfLevelZeroProviderTestSuite, umfLevelZeroProviderTest,
    ::testing::Values(
        LevelZeroProviderTestParams{createL0ParamsDeviceMemory, destroyL0Params,
                                    l0TestHelper.get_test_context(),
                                    UMF_MEMORY_TYPE_DEVICE, &l0Accessor},
        LevelZeroProviderTestParams{createL0ParamsSharedMemory, destroyL0Params,
                                    l0TestHelper.get_test_context(),
                                    UMF_MEMORY_TYPE_SHARED, &hostAccessor},
        LevelZeroProviderTestParams{createL0ParamsHostMemory, destroyL0Params,
                                    l0TestHelper.get_test_context(),
                                    UMF_MEMORY_TYPE_HOST, &hostAccessor}));

// TODO: it looks like there is some problem with IPC implementation in Level
// Zero on windows. Issue: #494
#ifdef _WIN32
GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfIpcTest);
#else
INSTANTIATE_TEST_SUITE_P(
    umfLevelZeroProviderTestSuite, umfIpcTest,
    ::testing::Values(ipcTestParams{
        umfProxyPoolOps(), nullptr, nullptr, umfLevelZeroMemoryProviderOps(),
        createL0ParamsDeviceMemory, destroyL0Params, &l0Accessor}));
#endif
