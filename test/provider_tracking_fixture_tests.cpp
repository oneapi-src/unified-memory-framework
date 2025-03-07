// Copyright (C) 2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <umf/memory_provider.h>
#include <umf/pools/pool_proxy.h>
#include <umf/providers/provider_file_memory.h>

#include "base.hpp"
#include "provider.hpp"

#include "cpp_helpers.hpp"
#include "test_helpers.h"
#ifndef _WIN32
#include "test_helpers_linux.h"
#endif

#include "poolFixtures.hpp"

#define FILE_PATH ((char *)"tmp_file")

struct provider_from_pool : public umf_test::provider_base_t {
    umf_memory_pool_handle_t pool;
    umf_result_t initialize(umf_memory_pool_handle_t _pool) noexcept {
        if (!_pool) {
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
        pool = _pool;
        return UMF_RESULT_SUCCESS;
    }
    umf_result_t alloc(size_t size, size_t align, void **ptr) noexcept {
        *ptr = umfPoolAlignedMalloc(pool, size, align);
        return (*ptr) ? UMF_RESULT_SUCCESS
                      : UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }
    umf_result_t free(void *ptr, size_t) noexcept {
        return umfPoolFree(pool, ptr);
    }
    const char *get_name() noexcept { return "provider_from_pool"; }

    virtual ~provider_from_pool() {
        if (pool) {
            umfPoolDestroy(pool);
            pool = nullptr;
        }
    }
};

umf_memory_provider_ops_t PROVIDER_FROM_POOL_OPS =
    umf::providerMakeCOps<provider_from_pool, umf_memory_pool_t>();

static void *providerFromPoolParamsCreate(void) {
    umf_file_memory_provider_params_handle_t paramsFile = NULL;
    umf_result_t umf_result =
        umfFileMemoryProviderParamsCreate(&paramsFile, FILE_PATH);
    EXPECT_EQ(umf_result, UMF_RESULT_SUCCESS);
    EXPECT_NE(paramsFile, nullptr);

    umf_memory_provider_handle_t providerFile = nullptr;
    umf_result = umfMemoryProviderCreate(umfFileMemoryProviderOps(), paramsFile,
                                         &providerFile);
    EXPECT_EQ(umf_result, UMF_RESULT_SUCCESS);
    EXPECT_NE(providerFile, nullptr);

    umf_memory_pool_handle_t poolProxyFile = nullptr;
    umf_result =
        umfPoolCreate(umfProxyPoolOps(), providerFile, nullptr,
                      UMF_POOL_CREATE_FLAG_OWN_PROVIDER, &poolProxyFile);
    EXPECT_EQ(umf_result, UMF_RESULT_SUCCESS);
    EXPECT_NE(poolProxyFile, nullptr);

    umf_result = umfFileMemoryProviderParamsDestroy(paramsFile);
    EXPECT_EQ(umf_result, UMF_RESULT_SUCCESS);
    paramsFile = nullptr;

    return poolProxyFile;
}

// TESTS

INSTANTIATE_TEST_SUITE_P(TrackingProviderPoolTest, umfPoolTest,
                         ::testing::Values(poolCreateExtParams{
                             umfProxyPoolOps(), nullptr, nullptr,
                             &PROVIDER_FROM_POOL_OPS,
                             providerFromPoolParamsCreate, nullptr}));

INSTANTIATE_TEST_SUITE_P(TrackingProviderMultiPoolTest, umfMultiPoolTest,
                         ::testing::Values(poolCreateExtParams{
                             umfProxyPoolOps(), nullptr, nullptr,
                             &PROVIDER_FROM_POOL_OPS,
                             providerFromPoolParamsCreate, nullptr}));
