// Copyright (C) 2024 Intel Corporation
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

using CUDAProviderTestParams =
    std::tuple<cuda_memory_provider_params_t, MemoryAccessor *>;

struct umfCUDAProviderTest
    : umf_test::test,
      ::testing::WithParamInterface<CUDAProviderTestParams> {

    void SetUp() override {
        test::SetUp();

        auto [cuda_params, accessor] = this->GetParam();
        params = cuda_params;
        memAccessor = accessor;
    }

    void TearDown() override { test::TearDown(); }

    cuda_memory_provider_params_t params;
    MemoryAccessor *memAccessor = nullptr;
};

TEST_P(umfCUDAProviderTest, basic) {
    const size_t size = 1024 * 8;
    const uint32_t pattern = 0xAB;
    CUcontext expected_current_context = get_current_context();

    // create CUDA provider
    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t umf_result =
        umfMemoryProviderCreate(umfCUDAMemoryProviderOps(), &params, &provider);
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
    ASSERT_EQ(actual_mem_context, (CUcontext)params.cuda_context_handle);

    CUcontext actual_current_context = get_current_context();
    ASSERT_EQ(actual_current_context, expected_current_context);

    umf_usm_memory_type_t memoryTypeActual =
        get_mem_type((CUcontext)params.cuda_context_handle, ptr);
    ASSERT_EQ(memoryTypeActual, params.memory_type);

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

TEST_P(umfCUDAProviderTest, getPageSize) {
    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t umf_result =
        umfMemoryProviderCreate(umfCUDAMemoryProviderOps(), &params, &provider);
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
        umfMemoryProviderCreate(umfCUDAMemoryProviderOps(), &params, &provider);
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
        umfMemoryProviderCreate(umfCUDAMemoryProviderOps(), &params, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    // try to alloc (int)-1
    void *ptr = nullptr;
    umf_result = umfMemoryProviderAlloc(provider, -1, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY);

    // in case of size == 0 we should got INVALID_ARGUMENT error
    // NOTE: this is invalid only for the DEVICE or SHARED allocations
    if (params.memory_type != UMF_MEMORY_TYPE_HOST) {
        umf_result = umfMemoryProviderAlloc(provider, 0, 0, &ptr);
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

    umf_result = umfMemoryProviderCreate(nullptr, &params, nullptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_P(umfCUDAProviderTest, getPageSizeInvalidArgs) {
    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t umf_result =
        umfMemoryProviderCreate(umfCUDAMemoryProviderOps(), &params, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    umf_result = umfMemoryProviderGetMinPageSize(provider, nullptr, nullptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umf_result = umfMemoryProviderGetRecommendedPageSize(provider, 0, nullptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umfMemoryProviderDestroy(provider);
}

// TODO add tests that mixes CUDA Memory Provider and Disjoint Pool

cuda_memory_provider_params_t cuParams_device_memory =
    create_cuda_prov_params(UMF_MEMORY_TYPE_DEVICE);
cuda_memory_provider_params_t cuParams_shared_memory =
    create_cuda_prov_params(UMF_MEMORY_TYPE_SHARED);
cuda_memory_provider_params_t cuParams_host_memory =
    create_cuda_prov_params(UMF_MEMORY_TYPE_HOST);

CUDAMemoryAccessor
    cuAccessor((CUcontext)cuParams_device_memory.cuda_context_handle,
               (CUdevice)cuParams_device_memory.cuda_device_handle);
HostMemoryAccessor hostAccessor;

INSTANTIATE_TEST_SUITE_P(
    umfCUDAProviderTestSuite, umfCUDAProviderTest,
    ::testing::Values(
        CUDAProviderTestParams{cuParams_device_memory, &cuAccessor},
        CUDAProviderTestParams{cuParams_shared_memory, &hostAccessor},
        CUDAProviderTestParams{cuParams_host_memory, &hostAccessor}));

// TODO: add IPC API
GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfIpcTest);
/*
INSTANTIATE_TEST_SUITE_P(umfCUDAProviderTestSuite, umfIpcTest,
                         ::testing::Values(ipcTestParams{
                             umfProxyPoolOps(), nullptr,
                             umfCUDAMemoryProviderOps(),
                             &cuParams_device_memory, &cuAccessor}));
*/
