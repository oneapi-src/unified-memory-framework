// Copyright (C) 2024-2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#ifdef _WIN32
//workaround for std::numeric_limits on windows
#define NOMINMAX
#endif

#include <mutex>

#include <umf/experimental/ctl.h>
#include <umf/experimental/memory_properties.h>
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

    int ret = utils_ze_init_level_zero();
    if (ret != 0) {
        fprintf(stderr, "utils_ze_init_level_zero() failed!\n");
        return;
    }

    ret = utils_ze_find_driver_with_gpu(&driver_idx, &hDriver_);
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

umf_result_t destroyL0Params(void *params) {
    return umfLevelZeroMemoryProviderParamsDestroy(
        static_cast<umf_level_zero_memory_provider_params_handle_t>(params));
}

struct LevelZeroProviderInit
    : public test,
      public ::testing::WithParamInterface<umf_usm_memory_type_t> {
    LevelZeroTestHelper l0TestHelper;
};

INSTANTIATE_TEST_SUITE_P(, LevelZeroProviderInit,
                         ::testing::Values(UMF_MEMORY_TYPE_HOST,
                                           UMF_MEMORY_TYPE_DEVICE,
                                           UMF_MEMORY_TYPE_SHARED),
                         ([](auto const &info) -> std::string {
                             static const char *names[] = {
                                 "UMF_MEMORY_TYPE_HOST",
                                 "UMF_MEMORY_TYPE_DEVICE",
                                 "UMF_MEMORY_TYPE_SHARED"};
                             return names[info.index];
                         }));

TEST_P(LevelZeroProviderInit, FailNullContext) {
    const umf_memory_provider_ops_t *ops = umfLevelZeroMemoryProviderOps();
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

    const umf_memory_provider_ops_t *ops = umfLevelZeroMemoryProviderOps();
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

TEST_F(LevelZeroProviderInit, FailNonNullDevice) {
    if (GetParam() != UMF_MEMORY_TYPE_HOST) {
        GTEST_SKIP() << "Host memory does not require device handle";
    }
    const umf_memory_provider_ops_t *ops = umfLevelZeroMemoryProviderOps();
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
    result = umfLevelZeroMemoryProviderParamsSetDevice(
        hParams, l0TestHelper.get_test_device());
    ASSERT_EQ(result, UMF_RESULT_SUCCESS);

    umf_memory_provider_handle_t provider = nullptr;
    result = umfMemoryProviderCreate(ops, hParams, &provider);
    ASSERT_EQ(result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umfLevelZeroMemoryProviderParamsDestroy(hParams);
}

static void
invalidResidentDevicesHandlesTestHelper(ze_device_handle_t *hDevices,
                                        uint32_t deviceCount) {
    const umf_memory_provider_ops_t *ops = umfLevelZeroMemoryProviderOps();
    ASSERT_NE(ops, nullptr);

    umf_level_zero_memory_provider_params_handle_t hParams = nullptr;
    const umf_result_t create_result =
        umfLevelZeroMemoryProviderParamsCreate(&hParams);
    ASSERT_EQ(create_result, UMF_RESULT_SUCCESS);

    const umf_result_t set_resident_result =
        umfLevelZeroMemoryProviderParamsSetResidentDevices(hParams, hDevices,
                                                           deviceCount);
    ASSERT_EQ(set_resident_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umfLevelZeroMemoryProviderParamsDestroy(hParams);
}

TEST_F(test, FailMismatchedResidentHandlesCount) {
    invalidResidentDevicesHandlesTestHelper(nullptr, 99);
}

TEST_F(test, FailRedundantResidentDeviceHandles) {
    std::vector<ze_device_handle_t> hDevices{
        reinterpret_cast<ze_device_handle_t>(0x100),
        reinterpret_cast<ze_device_handle_t>(0x101),
        reinterpret_cast<ze_device_handle_t>(0x100)};
    invalidResidentDevicesHandlesTestHelper(hDevices.data(), 3);
}

class LevelZeroMemoryAccessor : public MemoryAccessor {
  public:
    LevelZeroMemoryAccessor(ze_context_handle_t hContext,
                            ze_device_handle_t hDevice)
        : hDevice_(hDevice), hContext_(hContext) {}
    void fill(void *ptr, size_t size, const void *pattern,
              size_t pattern_size) override {
        ASSERT_NE(ptr, nullptr);

        int ret = utils_ze_level_zero_fill(hContext_, hDevice_, ptr, size,
                                           pattern, pattern_size);
        ASSERT_EQ(ret, 0);
    }

    void copy(void *dst_ptr, void *src_ptr, size_t size) override {
        ASSERT_NE(dst_ptr, nullptr);
        ASSERT_NE(src_ptr, nullptr);

        int ret = utils_ze_level_zero_copy(hContext_, hDevice_, dst_ptr,
                                           src_ptr, size);
        ASSERT_EQ(ret, 0);
    }

    const char *getName() override { return "LevelZeroMemoryAccessor"; }

  private:
    ze_device_handle_t hDevice_;
    ze_context_handle_t hContext_;
};

struct umfLevelZeroProviderTest
    : umf_test::test,
      ::testing::WithParamInterface<umf_usm_memory_type_t> {

    void SetUp() override {
        test::SetUp();

        umf_usm_memory_type_t memory_type = this->GetParam();
        umfExpectedMemoryType = memory_type;

        params = nullptr;
        memAccessor = nullptr;
        hContext = l0TestHelper.get_test_context();

        ASSERT_NE(hContext, nullptr);

        switch (memory_type) {
        case UMF_MEMORY_TYPE_DEVICE:
            zeMemoryTypeExpected = ZE_MEMORY_TYPE_DEVICE;
            params = create_level_zero_prov_params(
                l0TestHelper.get_test_context(), l0TestHelper.get_test_device(),
                memory_type);
            memAccessor = std::make_unique<LevelZeroMemoryAccessor>(
                l0TestHelper.get_test_context(),
                l0TestHelper.get_test_device());
            break;
        case UMF_MEMORY_TYPE_SHARED:
            zeMemoryTypeExpected = ZE_MEMORY_TYPE_SHARED;
            params = create_level_zero_prov_params(
                l0TestHelper.get_test_context(), l0TestHelper.get_test_device(),
                memory_type);
            memAccessor = std::make_unique<HostMemoryAccessor>();
            break;
        case UMF_MEMORY_TYPE_HOST:
            zeMemoryTypeExpected = ZE_MEMORY_TYPE_HOST;
            params = create_level_zero_prov_params(
                l0TestHelper.get_test_context(), nullptr, memory_type);
            memAccessor = std::make_unique<HostMemoryAccessor>();
            break;
        case UMF_MEMORY_TYPE_UNKNOWN:
            zeMemoryTypeExpected = ZE_MEMORY_TYPE_UNKNOWN;
            break;
        }

        ASSERT_NE(zeMemoryTypeExpected, ZE_MEMORY_TYPE_UNKNOWN);
    }

    void TearDown() override {
        if (params) {
            destroyL0Params(params);
        }

        test::TearDown();
    }

    LevelZeroTestHelper l0TestHelper;
    umf_level_zero_memory_provider_params_handle_t params = nullptr;

    std::unique_ptr<MemoryAccessor> memAccessor = nullptr;
    ze_context_handle_t hContext = nullptr;
    ze_memory_type_t zeMemoryTypeExpected = ZE_MEMORY_TYPE_UNKNOWN;
    umf_usm_memory_type_t umfExpectedMemoryType = UMF_MEMORY_TYPE_UNKNOWN;
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

    const char *name = nullptr;
    umf_result = umfMemoryProviderGetName(provider, &name);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_STREQ(name, "LEVEL_ZERO");

    umfMemoryProviderDestroy(provider);
}

TEST_P(umfLevelZeroProviderTest, ctl_stats) {
    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t ret = umfMemoryProviderCreate(umfLevelZeroMemoryProviderOps(),
                                               params, &provider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    size_t allocated = 0, peak = 0;
    ret = umfCtlGet("umf.provider.by_handle.{}.stats.allocated_memory",
                    &allocated, sizeof(allocated), provider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(allocated, 0u);

    ret = umfCtlGet("umf.provider.by_handle.{}.stats.peak_memory", &peak,
                    sizeof(peak), provider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(peak, 0u);

    void *ptr = nullptr;
    const size_t size = 1024 * 8;
    ret = umfMemoryProviderAlloc(provider, size, 0, &ptr);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    ret = umfCtlGet("umf.provider.by_handle.{}.stats.allocated_memory",
                    &allocated, sizeof(allocated), provider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(allocated, size);

    ret = umfCtlGet("umf.provider.by_handle.{}.stats.peak_memory", &peak,
                    sizeof(peak), provider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(peak, size);

    ret = umfMemoryProviderFree(provider, ptr, size);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfCtlGet("umf.provider.by_handle.{}.stats.allocated_memory",
                    &allocated, sizeof(allocated), provider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(allocated, 0u);

    ret = umfCtlGet("umf.provider.by_handle.{}.stats.peak_memory", &peak,
                    sizeof(peak), provider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(peak, size);

    ret = umfCtlExec("umf.provider.by_handle.{}.stats.peak_memory.reset", NULL,
                     0, provider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfCtlGet("umf.provider.by_handle.{}.stats.peak_memory", &peak,
                    sizeof(peak), provider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(peak, 0u);
    umfMemoryProviderDestroy(provider);
}

TEST_P(umfLevelZeroProviderTest, custom_name) {
    const char *custom = "my_level_zero";
    ASSERT_EQ(umfLevelZeroMemoryProviderParamsSetName(params, custom),
              UMF_RESULT_SUCCESS);

    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t res = umfMemoryProviderCreate(umfLevelZeroMemoryProviderOps(),
                                               params, &provider);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    const char *name = nullptr;
    res = umfMemoryProviderGetName(provider, &name);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    EXPECT_STREQ(name, custom);
    umfMemoryProviderDestroy(provider);
}

TEST(umfLevelZeroProviderOps, default_name_null_handle) {
    const char *name = nullptr;
    auto ret = umfLevelZeroMemoryProviderOps()->get_name(nullptr, &name);

    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    EXPECT_STREQ(name, "LEVEL_ZERO");
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
    umf_result =
        umfMemoryProviderGetLastNativeError(provider, &message, &error);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED); // TODO: see #1385
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

TEST_P(umfLevelZeroProviderTest, memProps) {
    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t umf_result = umfMemoryProviderCreate(
        umfLevelZeroMemoryProviderOps(), params, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    umf_memory_pool_handle_t pool = NULL;
    umf_result = umfPoolCreate(umfProxyPoolOps(), provider, NULL, 0, &pool);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    size_t size = 1024;
    void *ptr = umfPoolMalloc(pool, size);
    ASSERT_NE(ptr, nullptr);

    umf_memory_properties_handle_t props_handle = NULL;
    umf_result_t result = umfGetMemoryPropertiesHandle(ptr, &props_handle);
    ASSERT_EQ(result, UMF_RESULT_SUCCESS);
    ASSERT_NE(props_handle, nullptr);

    umf_usm_memory_type_t type = UMF_MEMORY_TYPE_UNKNOWN;
    result = umfGetMemoryProperty(
        props_handle, UMF_MEMORY_PROPERTY_POINTER_TYPE, &type, sizeof(type));
    ASSERT_EQ(result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(type, umfExpectedMemoryType);

    // base address and size
    void *baseAddress = nullptr;
    result =
        umfGetMemoryProperty(props_handle, UMF_MEMORY_PROPERTY_BASE_ADDRESS,
                             &baseAddress, sizeof(baseAddress));
    ASSERT_EQ(result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(baseAddress, ptr);

    size_t baseSize = 0;
    result = umfGetMemoryProperty(props_handle, UMF_MEMORY_PROPERTY_BASE_SIZE,
                                  &baseSize, sizeof(baseSize));
    ASSERT_EQ(result, UMF_RESULT_SUCCESS);
    ASSERT_GE(baseSize, size);

    int64_t bufferId = 0;
    result = umfGetMemoryProperty(props_handle, UMF_MEMORY_PROPERTY_BUFFER_ID,
                                  &bufferId, sizeof(bufferId));
    ASSERT_EQ(result, UMF_RESULT_SUCCESS);
    ASSERT_GE(bufferId, 0);

    if (umfExpectedMemoryType != UMF_MEMORY_TYPE_HOST) {
        ze_device_handle_t device = nullptr;
        result = umfGetMemoryProperty(props_handle, UMF_MEMORY_PROPERTY_DEVICE,
                                      &device, sizeof(device));
        ASSERT_EQ(result, UMF_RESULT_SUCCESS);
        ASSERT_EQ(device, l0TestHelper.get_test_device());
    }

    ze_context_handle_t context = nullptr;
    result = umfGetMemoryProperty(props_handle, UMF_MEMORY_PROPERTY_CONTEXT,
                                  &context, sizeof(context));
    ASSERT_EQ(result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(context, l0TestHelper.get_test_context());

    // check the props of pointer from the middle of alloc
    void *midPtr = static_cast<char *>(ptr) + size / 2;
    result = umfGetMemoryPropertiesHandle(midPtr, &props_handle);
    ASSERT_EQ(result, UMF_RESULT_SUCCESS);
    ASSERT_NE(props_handle, nullptr);
    result = umfGetMemoryProperty(
        props_handle, UMF_MEMORY_PROPERTY_POINTER_TYPE, &type, sizeof(type));
    ASSERT_EQ(result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(type, umfExpectedMemoryType);

    result =
        umfGetMemoryProperty(props_handle, UMF_MEMORY_PROPERTY_BASE_ADDRESS,
                             &baseAddress, sizeof(baseAddress));
    ASSERT_EQ(result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(baseAddress, ptr);

    umfFree(ptr);

    umfPoolDestroy(pool);
    umfMemoryProviderDestroy(provider);
}

// TODO add tests that mixes Level Zero Memory Provider and Disjoint Pool

INSTANTIATE_TEST_SUITE_P(
    umfLevelZeroProviderTestSuite, umfLevelZeroProviderTest,
    ::testing::Values(UMF_MEMORY_TYPE_HOST, UMF_MEMORY_TYPE_SHARED,
                      UMF_MEMORY_TYPE_DEVICE),
    ([](auto const &info) -> std::string {
        static const char *names[] = {"UMF_MEMORY_TYPE_HOST",
                                      "UMF_MEMORY_TYPE_SHARED",
                                      "UMF_MEMORY_TYPE_DEVICE"};
        return names[info.index];
    }));

LevelZeroTestHelper l0TestHelper;

void *createL0ParamsDeviceMemory() {
    return create_level_zero_prov_params(l0TestHelper.get_test_context(),
                                         l0TestHelper.get_test_device(),
                                         UMF_MEMORY_TYPE_DEVICE);
}

LevelZeroMemoryAccessor
    l0Accessor((ze_context_handle_t)l0TestHelper.get_test_context(),
               (ze_device_handle_t)l0TestHelper.get_test_device());
// TODO: it looks like there is some problem with IPC implementation in Level
// Zero on windows. Issue: #494
#ifdef _WIN32
GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfIpcTest);
#else
INSTANTIATE_TEST_SUITE_P(
    umfLevelZeroProviderTestSuite, umfIpcTest,
    ::testing::Values(ipcTestParams{
        umfProxyPoolOps(), nullptr, nullptr, umfLevelZeroMemoryProviderOps(),
        createL0ParamsDeviceMemory, destroyL0Params, &l0Accessor}),
    ipcTestParamsNameGen);
#endif
