// Copyright (C) 2024-2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#ifdef _WIN32
//workaround for std::numeric_limits on windows
#define NOMINMAX
#endif

#include <mutex>

#include <umf/providers/provider_cuda.h>

#include "cuda_helpers.h"
#include "ipcFixtures.hpp"
#include "pool.hpp"
#include "utils_load_library.h"

using umf_test::test;
using namespace umf_test;

class CUDATestHelper {
  public:
    CUDATestHelper();

    ~CUDATestHelper() {
        if (hContext_) {
            destroy_context(hContext_);
        }
    }

    CUcontext get_test_context() const { return hContext_; }

    CUdevice get_test_device() const { return hDevice_; }

  private:
    CUcontext hContext_ = nullptr;
    CUdevice hDevice_ = -1;
};

CUDATestHelper::CUDATestHelper() {
    int ret = init_cuda();
    if (ret != 0) {
        fprintf(stderr, "init_cuda() failed!\n");
        return;
    }

    ret = get_cuda_device(&hDevice_);
    if (ret != 0) {
        fprintf(stderr, "get_cuda_device() failed!\n");
        return;
    }

    ret = create_context(hDevice_, &hContext_);
    if (ret != 0) {
        fprintf(stderr, "create_context() failed!\n");
        return;
    }
}

umf_cuda_memory_provider_params_handle_t
create_cuda_prov_params(CUcontext context, CUdevice device,
                        umf_usm_memory_type_t memory_type, unsigned int flags) {
    umf_cuda_memory_provider_params_handle_t params = nullptr;

    umf_result_t res = umfCUDAMemoryProviderParamsCreate(&params);
    if (res != UMF_RESULT_SUCCESS) {
        return nullptr;
    }

    res = umfCUDAMemoryProviderParamsSetContext(params, context);
    if (res != UMF_RESULT_SUCCESS) {
        umfCUDAMemoryProviderParamsDestroy(params);
        return nullptr;
    }

    res = umfCUDAMemoryProviderParamsSetDevice(params, device);
    if (res != UMF_RESULT_SUCCESS) {
        umfCUDAMemoryProviderParamsDestroy(params);
        return nullptr;
    }

    res = umfCUDAMemoryProviderParamsSetMemoryType(params, memory_type);
    if (res != UMF_RESULT_SUCCESS) {
        umfCUDAMemoryProviderParamsDestroy(params);
        return nullptr;
    }

    res = umfCUDAMemoryProviderParamsSetAllocFlags(params, flags);
    if (res != UMF_RESULT_SUCCESS) {
        umfCUDAMemoryProviderParamsDestroy(params);
        return nullptr;
    }

    return params;
}

umf_result_t destroyCuParams(void *params) {
    return umfCUDAMemoryProviderParamsDestroy(
        (umf_cuda_memory_provider_params_handle_t)params);
}

class CUDAMemoryAccessor : public MemoryAccessor {
  public:
    CUDAMemoryAccessor(CUcontext hContext, CUdevice hDevice)
        : hDevice_(hDevice), hContext_(hContext) {}

    void fill(void *ptr, size_t size, const void *pattern,
              size_t pattern_size) {
        ASSERT_NE(hContext_, nullptr);
        ASSERT_GE(hDevice_, -1);
        ASSERT_NE(ptr, nullptr);

        int ret =
            cuda_fill(hContext_, hDevice_, ptr, size, pattern, pattern_size);
        ASSERT_EQ(ret, 0);
    }

    void copy(void *dst_ptr, void *src_ptr, size_t size) {
        ASSERT_NE(hContext_, nullptr);
        ASSERT_GE(hDevice_, -1);
        ASSERT_NE(dst_ptr, nullptr);
        ASSERT_NE(src_ptr, nullptr);

        int ret = cuda_copy(hContext_, hDevice_, dst_ptr, src_ptr, size);
        ASSERT_EQ(ret, 0);
    }

  private:
    CUdevice hDevice_;
    CUcontext hContext_;
};

struct umfCUDAProviderTest
    : umf_test::test,
      ::testing::WithParamInterface<umf_usm_memory_type_t> {

    void SetUp() override {
        test::SetUp();

        umf_usm_memory_type_t memory_type = this->GetParam();

        memAccessor = nullptr;
        expected_context = cudaTestHelper.get_test_context();
        expected_device = cudaTestHelper.get_test_device();
        params = create_cuda_prov_params(cudaTestHelper.get_test_context(),
                                         cudaTestHelper.get_test_device(),
                                         memory_type, 0 /* alloc flags */);
        ASSERT_NE(expected_context, nullptr);
        ASSERT_GE(expected_device, 0);

        switch (memory_type) {
        case UMF_MEMORY_TYPE_DEVICE:
            memAccessor = std::make_unique<CUDAMemoryAccessor>(
                cudaTestHelper.get_test_context(),
                cudaTestHelper.get_test_device());
            break;
        case UMF_MEMORY_TYPE_SHARED:
        case UMF_MEMORY_TYPE_HOST:
            memAccessor = std::make_unique<HostMemoryAccessor>();
            break;
        case UMF_MEMORY_TYPE_UNKNOWN:
            break;
        }

        expected_memory_type = memory_type;
    }

    void TearDown() override {
        if (params) {
            destroyCuParams(params);
        }

        test::TearDown();
    }

    CUDATestHelper cudaTestHelper;
    umf_cuda_memory_provider_params_handle_t params = nullptr;

    std::unique_ptr<MemoryAccessor> memAccessor = nullptr;
    CUcontext expected_context = nullptr;
    int expected_device = -1;
    umf_usm_memory_type_t expected_memory_type;
};

TEST_P(umfCUDAProviderTest, basic) {
    const size_t size = 1024 * 8;
    const uint32_t pattern = 0xAB;
    CUcontext expected_current_context = get_current_context();

    // create CUDA provider
    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t umf_result =
        umfMemoryProviderCreate(umfCUDAMemoryProviderOps(), params, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    size_t pageSize = 0;
    umf_result = umfMemoryProviderGetMinPageSize(provider, 0, &pageSize);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_GE(pageSize, 0);

    umf_result =
        umfMemoryProviderGetRecommendedPageSize(provider, 0, &pageSize);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_GE(pageSize, 0);

    void *ptr = nullptr;
    umf_result = umfMemoryProviderAlloc(provider, size, 128, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    // use the allocated memory - fill it with a 0xAB pattern
    memAccessor->fill(ptr, size, &pattern, sizeof(pattern));

    CUcontext actual_mem_context = get_mem_context(ptr);
    ASSERT_EQ(actual_mem_context, expected_context);

    CUcontext actual_current_context = get_current_context();
    ASSERT_EQ(actual_current_context, expected_current_context);

    umf_usm_memory_type_t memoryTypeActual =
        get_mem_type(actual_current_context, ptr);
    ASSERT_EQ(memoryTypeActual, expected_memory_type);

    // check if the pattern was successfully applied
    uint32_t *hostMemory = (uint32_t *)calloc(1, size);
    memAccessor->copy(hostMemory, ptr, size);
    for (size_t i = 0; i < size / sizeof(uint32_t); i++) {
        ASSERT_EQ(hostMemory[i], pattern);
    }
    free(hostMemory);

    umf_result = umfMemoryProviderFree(provider, ptr, size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umfMemoryProviderDestroy(provider);
}

TEST_P(umfCUDAProviderTest, getPageSize) {
    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t umf_result =
        umfMemoryProviderCreate(umfCUDAMemoryProviderOps(), params, &provider);
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

TEST_P(umfCUDAProviderTest, getName) {
    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t umf_result =
        umfMemoryProviderCreate(umfCUDAMemoryProviderOps(), params, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    const char *name = umfMemoryProviderGetName(provider);
    ASSERT_STREQ(name, "CUDA");

    umfMemoryProviderDestroy(provider);
}

TEST_P(umfCUDAProviderTest, allocInvalidSize) {
    CUcontext expected_current_context = get_current_context();
    // create CUDA provider
    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t umf_result =
        umfMemoryProviderCreate(umfCUDAMemoryProviderOps(), params, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    void *ptr = nullptr;

    // NOTE: some scenarios are invalid only for the DEVICE allocations
    if (expected_memory_type == UMF_MEMORY_TYPE_DEVICE) {
        // try to alloc SIZE_MAX
        umf_result = umfMemoryProviderAlloc(provider, SIZE_MAX, 0, &ptr);
        ASSERT_EQ(ptr, nullptr);
        ASSERT_EQ(umf_result, UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY);

        // in case of size == 0 we should got INVALID_ARGUMENT error
        umf_result = umfMemoryProviderAlloc(provider, 0, 0, &ptr);
        ASSERT_EQ(ptr, nullptr);
        ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    }

    CUcontext actual_current_context = get_current_context();
    ASSERT_EQ(actual_current_context, expected_current_context);

    umfMemoryProviderDestroy(provider);
}

TEST_P(umfCUDAProviderTest, providerCreateInvalidArgs) {
    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t umf_result =
        umfMemoryProviderCreate(umfCUDAMemoryProviderOps(), nullptr, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umf_result = umfMemoryProviderCreate(nullptr, params, nullptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_P(umfCUDAProviderTest, getPageSizeInvalidArgs) {
    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t umf_result =
        umfMemoryProviderCreate(umfCUDAMemoryProviderOps(), params, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    umf_result = umfMemoryProviderGetMinPageSize(provider, nullptr, nullptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umf_result = umfMemoryProviderGetRecommendedPageSize(provider, 0, nullptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umfMemoryProviderDestroy(provider);
}

TEST_P(umfCUDAProviderTest, cudaProviderDefaultParams) {
    umf_cuda_memory_provider_params_handle_t defaultParams = nullptr;
    umf_result_t umf_result = umfCUDAMemoryProviderParamsCreate(&defaultParams);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result = umfCUDAMemoryProviderParamsSetMemoryType(defaultParams,
                                                          expected_memory_type);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    // NOTE: we intentionally do not set any context and device params

    umf_memory_provider_handle_t provider = nullptr;
    umf_result = umfMemoryProviderCreate(umfCUDAMemoryProviderOps(),
                                         defaultParams, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    // do single alloc and check if the context and device id of allocated
    // memory are correct

    void *ptr = nullptr;
    umf_result = umfMemoryProviderAlloc(provider, 128, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    CUcontext actual_mem_context = get_mem_context(ptr);
    ASSERT_EQ(actual_mem_context, expected_context);

    int actual_device = get_mem_device(ptr);
    ASSERT_EQ(actual_device, expected_device);

    umf_result = umfMemoryProviderFree(provider, ptr, 128);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umfMemoryProviderDestroy(provider);
    umfCUDAMemoryProviderParamsDestroy(defaultParams);
}

TEST_P(umfCUDAProviderTest, cudaProviderNullParams) {
    umf_result_t res = umfCUDAMemoryProviderParamsCreate(nullptr);
    EXPECT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfCUDAMemoryProviderParamsSetContext(nullptr, expected_context);
    EXPECT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfCUDAMemoryProviderParamsSetDevice(nullptr, 1);
    EXPECT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res =
        umfCUDAMemoryProviderParamsSetMemoryType(nullptr, expected_memory_type);
    EXPECT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res =
        umfCUDAMemoryProviderParamsSetAllocFlags(nullptr, 1);
    EXPECT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_P(umfCUDAProviderTest, cudaProviderInvalidCreate) {
    CUdevice device;
    int ret = get_cuda_device(&device);
    ASSERT_EQ(ret, 0);

    CUcontext ctx;
    ret = create_context(device, &ctx);
    ASSERT_EQ(ret, 0);

    // wrong memory type
    umf_cuda_memory_provider_params_handle_t params1 =
        create_cuda_prov_params(ctx, device, (umf_usm_memory_type_t)0xFFFF, 0);
    ASSERT_NE(params1, nullptr);
    umf_memory_provider_handle_t provider;
    umf_result_t umf_result = umfMemoryProviderCreate(
        umfCUDAMemoryProviderOps(), params1, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // wrong context
    params1 = create_cuda_prov_params((CUcontext)-1, device, UMF_MEMORY_TYPE_HOST, 0);
    ASSERT_NE(params1, nullptr);
    umf_result = umfMemoryProviderCreate(umfCUDAMemoryProviderOps(), params1, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // wrong device
    params1 = create_cuda_prov_params(ctx, (CUdevice)-1, UMF_MEMORY_TYPE_HOST, 0);
    ASSERT_NE(params1, nullptr);
    umf_result = umfMemoryProviderCreate(umfCUDAMemoryProviderOps(), params1, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_P(umfCUDAProviderTest, multiContext) {
    CUdevice device;
    int ret = get_cuda_device(&device);
    ASSERT_EQ(ret, 0);

    // create two CUDA contexts and two providers
    CUcontext ctx1, ctx2;
    ret = create_context(device, &ctx1);
    ASSERT_EQ(ret, 0);
    ret = create_context(device, &ctx2);
    ASSERT_EQ(ret, 0);

    umf_cuda_memory_provider_params_handle_t params1 =
        create_cuda_prov_params(ctx1, device, UMF_MEMORY_TYPE_HOST, 0);
    ASSERT_NE(params1, nullptr);
    umf_memory_provider_handle_t provider1;
    umf_result_t umf_result = umfMemoryProviderCreate(
        umfCUDAMemoryProviderOps(), params1, &provider1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider1, nullptr);
    umf_result = umfCUDAMemoryProviderParamsDestroy(params1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_cuda_memory_provider_params_handle_t params2 =
        create_cuda_prov_params(ctx2, device, UMF_MEMORY_TYPE_HOST, 0);
    ASSERT_NE(params2, nullptr);
    umf_memory_provider_handle_t provider2;
    umf_result = umfMemoryProviderCreate(umfCUDAMemoryProviderOps(), params2,
                                         &provider2);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider2, nullptr);
    umf_result = umfCUDAMemoryProviderParamsDestroy(params2);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    // use the providers
    // allocate from 1, then from 2, then free 1, then free 2
    void *ptr1, *ptr2;
    const int size = 128;
    // NOTE: we use ctx1 here
    umf_result = umfMemoryProviderAlloc(provider1, size, 0, &ptr1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr1, nullptr);

    // NOTE: we use ctx2 here
    umf_result = umfMemoryProviderAlloc(provider2, size, 0, &ptr2);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr2, nullptr);

    // even if we change the context, we should be able to free the memory
    ret = set_context(ctx2, NULL);
    ASSERT_EQ(ret, 0);
    // free memory from ctx1
    umf_result = umfMemoryProviderFree(provider1, ptr1, size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    ret = set_context(ctx1, NULL);
    ASSERT_EQ(ret, 0);
    umf_result = umfMemoryProviderFree(provider2, ptr2, size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    // cleanup
    umfMemoryProviderDestroy(provider2);
    umfMemoryProviderDestroy(provider1);
    ret = destroy_context(ctx1);
    ASSERT_EQ(ret, 0);
    ret = destroy_context(ctx2);
    ASSERT_EQ(ret, 0);
}

struct umfCUDAProviderAllocFlagsTest
    : umf_test::test,
      ::testing::WithParamInterface<
          std::tuple<umf_usm_memory_type_t, unsigned int>> {

    void SetUp() override {
        test::SetUp();

        get_cuda_device(&device);
        create_context(device, &context);
    }

    void TearDown() override {
        destroy_context(context);

        test::TearDown();
    }

    CUdevice device;
    CUcontext context;
};

TEST_P(umfCUDAProviderAllocFlagsTest, cudaAllocFlags) {
    auto [memory_type, test_flags] = this->GetParam();

    umf_cuda_memory_provider_params_handle_t test_params =
        create_cuda_prov_params(context, device, memory_type, test_flags);

    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t umf_result = umfMemoryProviderCreate(
        umfCUDAMemoryProviderOps(), test_params, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    void *ptr = nullptr;
    umf_result = umfMemoryProviderAlloc(provider, 128, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    if (memory_type == UMF_MEMORY_TYPE_HOST) {
        // check if the memory allocation flag is set correctly
        unsigned int flags = get_mem_host_alloc_flags(ptr);
        ASSERT_TRUE(flags & test_flags);
    }

    umf_result = umfMemoryProviderFree(provider, ptr, 128);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umfMemoryProviderDestroy(provider);
    umfCUDAMemoryProviderParamsDestroy(test_params);
}

TEST_P(umfCUDAProviderAllocFlagsTest, reuseParams) {
    auto [memory_type, test_flags] = this->GetParam();

    // first, create a provider for SHARED memory type with empty alloc flags,
    // and the reuse the test_params to create a provider for test params
    umf_cuda_memory_provider_params_handle_t test_params =
        create_cuda_prov_params(context, device, UMF_MEMORY_TYPE_SHARED, 0);

    umf_memory_provider_handle_t provider = nullptr;

    umf_result_t umf_result = umfMemoryProviderCreate(
        umfCUDAMemoryProviderOps(), test_params, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    void *ptr = nullptr;
    umf_result = umfMemoryProviderAlloc(provider, 128, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    umf_result = umfMemoryProviderFree(provider, ptr, 128);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umfMemoryProviderDestroy(provider);

    // reuse the test_params to create a provider for test params
    umf_result =
        umfCUDAMemoryProviderParamsSetMemoryType(test_params, memory_type);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result =
        umfCUDAMemoryProviderParamsSetAllocFlags(test_params, test_flags);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result = umfMemoryProviderCreate(umfCUDAMemoryProviderOps(),
                                         test_params, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    umf_result = umfMemoryProviderAlloc(provider, 128, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    if (memory_type == UMF_MEMORY_TYPE_HOST) {
        // check if the memory allocation flag is set correctly
        unsigned int flags = get_mem_host_alloc_flags(ptr);
        ASSERT_TRUE(flags & test_flags);
    }

    umf_result = umfMemoryProviderFree(provider, ptr, 128);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umfMemoryProviderDestroy(provider);

    umfCUDAMemoryProviderParamsDestroy(test_params);
}

// TODO add tests that mixes CUDA Memory Provider and Disjoint Pool

INSTANTIATE_TEST_SUITE_P(umfCUDAProviderTestSuite, umfCUDAProviderTest,
                         ::testing::Values(UMF_MEMORY_TYPE_DEVICE,
                                           UMF_MEMORY_TYPE_SHARED,
                                           UMF_MEMORY_TYPE_HOST));

INSTANTIATE_TEST_SUITE_P(
    umfCUDAProviderAllocFlagsTestSuite, umfCUDAProviderAllocFlagsTest,
    ::testing::Values(
        std::make_tuple(UMF_MEMORY_TYPE_SHARED, CU_MEM_ATTACH_GLOBAL),
        std::make_tuple(UMF_MEMORY_TYPE_SHARED, CU_MEM_ATTACH_HOST),
        std::make_tuple(UMF_MEMORY_TYPE_HOST, CU_MEMHOSTALLOC_PORTABLE),
        std::make_tuple(UMF_MEMORY_TYPE_HOST, CU_MEMHOSTALLOC_DEVICEMAP),
        std::make_tuple(UMF_MEMORY_TYPE_HOST, CU_MEMHOSTALLOC_WRITECOMBINED)));

// TODO: add IPC API
GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfIpcTest);
/*
INSTANTIATE_TEST_SUITE_P(umfCUDAProviderTestSuite, umfIpcTest,
                         ::testing::Values(ipcTestParams{
                             umfProxyPoolOps(), nullptr,
                             umfCUDAMemoryProviderOps(),
                             cuParams_device_memory.get(), &cuAccessor, false}));
*/
