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
        ASSERT_NE(ptr, nullptr);

        int ret =
            cuda_fill(hContext_, hDevice_, ptr, size, pattern, pattern_size);
        ASSERT_EQ(ret, 0);
    }

    void copy(void *dst_ptr, void *src_ptr, size_t size) {
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

        auto [cu_params, accessor] = this->GetParam();
        params = cu_params;

        hDevice = params.cuda_device_handle;
        hContext = (CUcontext)params.cuda_context_handle;

        ASSERT_GE(hDevice, 0);
        ASSERT_NE(hContext, nullptr);

        switch (params.memory_type) {
        case UMF_MEMORY_TYPE_DEVICE:
            memoryTypeExpected = UMF_MEMORY_TYPE_DEVICE;
            break;
        case UMF_MEMORY_TYPE_SHARED:
            memoryTypeExpected = UMF_MEMORY_TYPE_SHARED;
            break;
        case UMF_MEMORY_TYPE_HOST:
            memoryTypeExpected = UMF_MEMORY_TYPE_HOST;
            break;
        case UMF_MEMORY_TYPE_UNKNOWN:
            memoryTypeExpected = UMF_MEMORY_TYPE_UNKNOWN;
            break;
        }

        ASSERT_NE(memoryTypeExpected, UMF_MEMORY_TYPE_UNKNOWN);
        memAccessor = accessor;
    }

    void TearDown() override {
        int ret = destroy_context(hContext);
        ASSERT_EQ(ret, 0);
        test::TearDown();
    }

    cuda_memory_provider_params_t params;
    CUdevice hDevice = 0;
    CUcontext hContext = nullptr;
    umf_usm_memory_type_t memoryTypeExpected = UMF_MEMORY_TYPE_UNKNOWN;
    MemoryAccessor *memAccessor = nullptr;
};

GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfCUDAProviderTest);

TEST_P(umfCUDAProviderTest, basic) {
    const size_t size = 1024 * 8;
    const uint32_t pattern = 0xAB;

    // create CUDA provider
    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t umf_result =
        umfMemoryProviderCreate(umfCUDAMemoryProviderOps(), &params, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    void *ptr = nullptr;
    umf_result = umfMemoryProviderAlloc(provider, size, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    // use the allocated memory - fill it with a 0xAB pattern
    memAccessor->fill(ptr, size, &pattern, sizeof(pattern));

    umf_usm_memory_type_t memoryTypeActual = get_mem_type(hContext, ptr);
    ASSERT_EQ(memoryTypeActual, memoryTypeExpected);

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

// TODO add CUDA Memory Provider specific tests
// TODO add negative test and check for CUDA native errors
// TODO add tests that mixes CUDA Memory Provider and Disjoint Pool

cuda_memory_provider_params_t cuParams_device_memory =
    create_cuda_prov_params(UMF_MEMORY_TYPE_DEVICE);
cuda_memory_provider_params_t cuParams_shared_memory =
    create_cuda_prov_params(UMF_MEMORY_TYPE_SHARED);
cuda_memory_provider_params_t cuParams_host_memory =
    create_cuda_prov_params(UMF_MEMORY_TYPE_HOST);

CUDAMemoryAccessor
    cuAccessor((CUcontext)cuParams_device_memory.cuda_context_handle,
               cuParams_device_memory.cuda_device_handle);

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
                             &cuParams_device_memory, &l0Accessor}));
*/
