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
    int ret = get_cuda_device(&hDevice_);
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
                        umf_usm_memory_type_t memory_type) {
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

    return params;
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

typedef void *(*pfnProviderParamsCreate)();
typedef umf_result_t (*pfnProviderParamsDestroy)(void *);

using CUDAProviderTestParams =
    std::tuple<pfnProviderParamsCreate, pfnProviderParamsDestroy, CUcontext,
               umf_usm_memory_type_t, MemoryAccessor *>;

struct umfCUDAProviderTest
    : umf_test::test,
      ::testing::WithParamInterface<CUDAProviderTestParams> {

    void SetUp() override {
        test::SetUp();

        auto [params_create, params_destroy, cu_context, memory_type,
              accessor] = this->GetParam();

        params = nullptr;
        if (params_create) {
            params = (umf_cuda_memory_provider_params_handle_t)params_create();
        }
        paramsDestroy = params_destroy;

        memAccessor = accessor;
        expected_context = cu_context;
        expected_memory_type = memory_type;
    }

    void TearDown() override {
        if (paramsDestroy) {
            paramsDestroy(params);
        }

        test::TearDown();
    }

    umf_cuda_memory_provider_params_handle_t params;
    pfnProviderParamsDestroy paramsDestroy = nullptr;

    MemoryAccessor *memAccessor = nullptr;
    CUcontext expected_context;
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
        create_cuda_prov_params(ctx1, device, UMF_MEMORY_TYPE_HOST);
    ASSERT_NE(params1, nullptr);
    umf_memory_provider_handle_t provider1;
    umf_result_t umf_result = umfMemoryProviderCreate(
        umfCUDAMemoryProviderOps(), params1, &provider1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider1, nullptr);
    umf_result = umfCUDAMemoryProviderParamsDestroy(params1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_cuda_memory_provider_params_handle_t params2 =
        create_cuda_prov_params(ctx2, device, UMF_MEMORY_TYPE_HOST);
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

// TODO add tests that mixes CUDA Memory Provider and Disjoint Pool

CUDATestHelper cudaTestHelper;

void *createCuParamsDeviceMemory() {
    return create_cuda_prov_params(cudaTestHelper.get_test_context(),
                                   cudaTestHelper.get_test_device(),
                                   UMF_MEMORY_TYPE_DEVICE);
}
void *createCuParamsSharedMemory() {
    return create_cuda_prov_params(cudaTestHelper.get_test_context(),
                                   cudaTestHelper.get_test_device(),
                                   UMF_MEMORY_TYPE_SHARED);
}
void *createCuParamsHostMemory() {
    return create_cuda_prov_params(cudaTestHelper.get_test_context(),
                                   cudaTestHelper.get_test_device(),
                                   UMF_MEMORY_TYPE_HOST);
}

umf_result_t destroyCuParams(void *params) {
    return umfCUDAMemoryProviderParamsDestroy(
        (umf_cuda_memory_provider_params_handle_t)params);
}

CUDAMemoryAccessor cuAccessor(cudaTestHelper.get_test_context(),
                              cudaTestHelper.get_test_device());
HostMemoryAccessor hostAccessor;
INSTANTIATE_TEST_SUITE_P(
    umfCUDAProviderTestSuite, umfCUDAProviderTest,
    ::testing::Values(
        CUDAProviderTestParams{createCuParamsDeviceMemory, destroyCuParams,
                               cudaTestHelper.get_test_context(),
                               UMF_MEMORY_TYPE_DEVICE, &cuAccessor},
        CUDAProviderTestParams{createCuParamsSharedMemory, destroyCuParams,
                               cudaTestHelper.get_test_context(),
                               UMF_MEMORY_TYPE_SHARED, &hostAccessor},
        CUDAProviderTestParams{createCuParamsHostMemory, destroyCuParams,
                               cudaTestHelper.get_test_context(),
                               UMF_MEMORY_TYPE_HOST, &hostAccessor}));

// TODO: add IPC API
GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfIpcTest);
/*
INSTANTIATE_TEST_SUITE_P(umfCUDAProviderTestSuite, umfIpcTest,
                         ::testing::Values(ipcTestParams{
                             umfProxyPoolOps(), nullptr,
                             umfCUDAMemoryProviderOps(),
                             cuParams_device_memory.get(), &cuAccessor, false}));
*/
