// Copyright (C) 2023-2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "umf/pools/pool_jemalloc.h"
#include "umf/providers/provider_os_memory.h"

#include "pool.hpp"
#include "poolFixtures.hpp"

using umf_test::test;
using namespace umf_test;

using os_params_unique_handle_t =
    std::unique_ptr<umf_os_memory_provider_params_t,
                    decltype(&umfOsMemoryProviderParamsDestroy)>;

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

INSTANTIATE_TEST_SUITE_P(
    jemallocPoolTest, umfPoolTest,
    ::testing::Values(poolCreateExtParams{umfJemallocPoolOps(), nullptr,
                                          nullptr, umfOsMemoryProviderOps(),
                                          createOsMemoryProviderParams,
                                          destroyOsMemoryProviderParams},
                      poolCreateExtParams{umfJemallocPoolOps(), nullptr,
                                          nullptr, &BA_GLOBAL_PROVIDER_OPS,
                                          nullptr, nullptr}));

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
