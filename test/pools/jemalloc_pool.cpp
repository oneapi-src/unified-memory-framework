// Copyright (C) 2023-2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "umf/pools/pool_jemalloc.h"
#include "umf/providers/provider_os_memory.h"

#include "pool.hpp"
#include "poolFixtures.hpp"

using umf_test::test;
using namespace umf_test;

using void_unique_ptr = std::unique_ptr<void, decltype(&free)>;

void *createOsMemoryProviderParams() {
    umf_os_memory_provider_params_handle_t params = nullptr;
    umf_result_t res = umfOsMemoryProviderParamsCreate(&params);
    if (res != UMF_RESULT_SUCCESS) {
        throw std::runtime_error("Failed to create os memory provider params");
    }

    return params;
}

umf_result_t destroyOsMemoryProviderParams(void *params) {
    return umfOsMemoryProviderParamsDestroy(
        (umf_os_memory_provider_params_handle_t)params);
}

void *createFixedMemoryProviderParams() {
    // Allocate a memory buffer to use with the fixed memory provider.
    // The umfPoolTest.malloc_compliance test requires a lot of memory.
    size_t memory_size = (1UL << 31);
    static void_unique_ptr memory_buffer =
        void_unique_ptr(malloc(memory_size), free);
    if (memory_buffer.get() == NULL) {
        throw std::runtime_error(
            "Failed to allocate memory for Fixed memory provider");
    }

    umf_fixed_memory_provider_params_handle_t params = nullptr;
    umf_result_t res = umfFixedMemoryProviderParamsCreate(
        &params, memory_buffer.get(), memory_size);
    if (res != UMF_RESULT_SUCCESS) {
        throw std::runtime_error(
            "Failed to create Fixed memory provider params");
    }

    return params;
}

umf_result_t destroyFixedMemoryProviderParams(void *params) {
    return umfFixedMemoryProviderParamsDestroy(
        (umf_fixed_memory_provider_params_handle_t)params);
}

template <unsigned arenas = 0> void *createJemallocParams() {
    umf_jemalloc_pool_params_handle_t params = nullptr;
    auto ret = umfJemallocPoolParamsCreate(&params);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    if constexpr (arenas != 0) {
        ret = umfJemallocPoolParamsSetNumArenas(params, arenas);
        EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    }
    return params;
}

umf_result_t destroyJemallocParams(void *params) {
    return umfJemallocPoolParamsDestroy(
        (umf_jemalloc_pool_params_handle_t)params);
}

INSTANTIATE_TEST_SUITE_P(
    jemallocPoolTest, umfPoolTest,
    ::testing::Values(
        poolCreateExtParams{
            umfJemallocPoolOps(), nullptr, nullptr, umfOsMemoryProviderOps(),
            createOsMemoryProviderParams, destroyOsMemoryProviderParams},
        poolCreateExtParams{
            umfJemallocPoolOps(), nullptr, nullptr, umfFixedMemoryProviderOps(),
            createFixedMemoryProviderParams, destroyFixedMemoryProviderParams},
        poolCreateExtParams{umfJemallocPoolOps(), createJemallocParams,
                            destroyJemallocParams, umfOsMemoryProviderOps(),
                            createOsMemoryProviderParams,
                            destroyOsMemoryProviderParams},
        poolCreateExtParams{umfJemallocPoolOps(), createJemallocParams<1>,
                            destroyJemallocParams, umfOsMemoryProviderOps(),
                            createOsMemoryProviderParams,
                            destroyOsMemoryProviderParams}));

// this test makes sure that jemalloc does not use
// memory provider to allocate metadata (and hence
// is suitable for cases where memory is not accessible
// on the host)
TEST_F(test, metadataNotAllocatedUsingProvider) {
    static constexpr size_t allocSize = 1024;
    static constexpr size_t numAllocs = 1024;

    // set coarse grain allocations to PROT_NONE so that we can be sure
    // jemalloc does not touch any of the allocated memory

    auto providerParamsCreate = []() {
        umf_os_memory_provider_params_handle_t params = nullptr;
        umf_result_t res = umfOsMemoryProviderParamsCreate(&params);
        if (res != UMF_RESULT_SUCCESS) {
            throw std::runtime_error(
                "Failed to create OS Memory Provider params");
        }
        res =
            umfOsMemoryProviderParamsSetProtection(params, UMF_PROTECTION_NONE);
        if (res != UMF_RESULT_SUCCESS) {
            throw std::runtime_error(
                "Failed to set OS Memory Provider params protection");
        }
        return (void *)params;
    };

    auto providerParamsDestroy = [](void *params) {
        umf_result_t res = umfOsMemoryProviderParamsDestroy(
            (umf_os_memory_provider_params_handle_t)params);
        if (res != UMF_RESULT_SUCCESS) {
            throw std::runtime_error(
                "Failed to destroy OS Memory Provider params");
        }
        return res;
    };

    auto pool = poolCreateExtUnique({
        umfJemallocPoolOps(),
        nullptr,
        nullptr,
        umfOsMemoryProviderOps(),
        (pfnProviderParamsCreate)providerParamsCreate,
        (pfnProviderParamsDestroy)providerParamsDestroy,
    });

    std::vector<std::shared_ptr<void>> allocs;
    for (size_t i = 0; i < numAllocs; i++) {
        allocs.emplace_back(
            umfPoolMalloc(pool.get(), allocSize),
            [pool = pool.get()](void *ptr) { umfPoolFree(pool, ptr); });
    }
}

TEST_F(test, jemallocPoolNullParams) {
    auto ret = umfJemallocPoolParamsSetNumArenas(NULL, 1);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_F(test, jemallocPoolParams) {
    umf_jemalloc_pool_params_handle_t params = nullptr;
    auto ret = umfJemallocPoolParamsCreate(&params);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfJemallocPoolParamsSetNumArenas(params, 1);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfJemallocPoolParamsDestroy(params);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
}

TEST_F(test, jemallocPoolParamsInvalid) {
    umf_jemalloc_pool_params_handle_t params = nullptr;
    auto ret = umfJemallocPoolParamsCreate(&params);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfJemallocPoolParamsSetNumArenas(params, SIZE_MAX);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    umf_os_memory_provider_params_handle_t provider_params = nullptr;
    ret = umfOsMemoryProviderParamsCreate(&provider_params);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    umf_memory_provider_handle_t provider;
    ret = umfMemoryProviderCreate(umfOsMemoryProviderOps(), provider_params,
                                  &provider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    umf_memory_pool_handle_t pool;
    ret = umfPoolCreate(umfJemallocPoolOps(), provider, params, 0, &pool);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umfMemoryProviderDestroy(provider);

    ret = umfJemallocPoolParamsDestroy(params);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    ret = umfOsMemoryProviderParamsDestroy(provider_params);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
}
