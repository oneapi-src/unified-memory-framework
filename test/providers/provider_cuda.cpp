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
    void init(CUcontext hContext, CUdevice hDevice) {
        hDevice_ = hDevice;
        hContext_ = hContext;
    }

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
    std::tuple<umf_usm_memory_type_t, MemoryAccessor *>;

struct umfCUDAProviderTest
    : umf_test::test,
      ::testing::WithParamInterface<CUDAProviderTestParams> {

    void SetUp() override {
        test::SetUp();

        auto [memory_type, accessor] = this->GetParam();
        params = create_cuda_prov_params(memory_type);
        memAccessor = accessor;
        if (memory_type == UMF_MEMORY_TYPE_DEVICE) {
            ((CUDAMemoryAccessor *)memAccessor)
                ->init((CUcontext)params.cuda_context_handle,
                       params.cuda_device_handle);
        }
    }

    void TearDown() override {
        if (params.cuda_context_handle) {
            int ret = destroy_context((CUcontext)params.cuda_context_handle);
            ASSERT_EQ(ret, 0);
        }
        test::TearDown();
    }

    cuda_memory_provider_params_t params;
    MemoryAccessor *memAccessor = nullptr;
};

TEST_P(umfCUDAProviderTest, basic) {
    const size_t size = 1024 * 8;
    const uint32_t pattern = 0xAB;

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

TEST_P(umfCUDAProviderTest, allocInvalidSize) {
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

    // destroy context and try to alloc some memory
    destroy_context((CUcontext)params.cuda_context_handle);
    params.cuda_context_handle = 0;
    umf_result = umfMemoryProviderAlloc(provider, 128, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC);

    const char *message;
    int32_t error;
    umfMemoryProviderGetLastNativeError(provider, &message, &error);
    ASSERT_EQ(error, CUDA_ERROR_INVALID_CONTEXT);
    const char *expected_message =
        "CUDA_ERROR_INVALID_CONTEXT - invalid device context";
    ASSERT_EQ(strncmp(message, expected_message, strlen(expected_message)), 0);
}

// TODO add tests that mixes CUDA Memory Provider and Disjoint Pool

CUDAMemoryAccessor cuAccessor;
HostMemoryAccessor hostAccessor;

INSTANTIATE_TEST_SUITE_P(
    umfCUDAProviderTestSuite, umfCUDAProviderTest,
    ::testing::Values(
        CUDAProviderTestParams{UMF_MEMORY_TYPE_DEVICE, &cuAccessor},
        CUDAProviderTestParams{UMF_MEMORY_TYPE_SHARED, &hostAccessor},
        CUDAProviderTestParams{UMF_MEMORY_TYPE_HOST, &hostAccessor}));

// TODO: add IPC API
GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfIpcTest);
/*
INSTANTIATE_TEST_SUITE_P(umfCUDAProviderTestSuite, umfIpcTest,
                         ::testing::Values(ipcTestParams{
                             umfProxyPoolOps(), nullptr,
                             umfCUDAMemoryProviderOps(),
                             &cuParams_device_memory, &l0Accessor}));
*/
