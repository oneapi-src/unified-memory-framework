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

os_params_unique_handle_t createOsMemoryProviderParams() {
    umf_os_memory_provider_params_handle_t params = nullptr;
    umf_result_t res = umfOsMemoryProviderParamsCreate(&params);
    if (res != UMF_RESULT_SUCCESS) {
        throw std::runtime_error("Failed to create os memory provider params");
    }

    return os_params_unique_handle_t(params, &umfOsMemoryProviderParamsDestroy);
}
auto defaultParams = createOsMemoryProviderParams();

INSTANTIATE_TEST_SUITE_P(jemallocPoolTest, umfPoolTest,
                         ::testing::Values(poolCreateExtParams{
                             umfJemallocPoolOps(), nullptr,
                             umfOsMemoryProviderOps(), defaultParams.get()}));

// this test makes sure that jemalloc does not use
// memory provider to allocate metadata (and hence
// is suitable for cases where memory is not accessible
// on the host)
TEST_F(test, metadataNotAllocatedUsingProvider) {
    static constexpr size_t allocSize = 1024;
    static constexpr size_t numAllocs = 1024;

    // set coarse grain allocations to PROT_NONE so that we can be sure
    // jemalloc does not touch any of the allocated memory
    umf_os_memory_provider_params_handle_t params = nullptr;
    umf_result_t res = umfOsMemoryProviderParamsCreate(&params);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    res = umfOsMemoryProviderParamsSetProtection(params, UMF_PROTECTION_NONE);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);

    auto pool = poolCreateExtUnique(
        {umfJemallocPoolOps(), nullptr, umfOsMemoryProviderOps(), params});

    res = umfOsMemoryProviderParamsDestroy(params);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);

    std::vector<std::shared_ptr<void>> allocs;
    for (size_t i = 0; i < numAllocs; i++) {
        allocs.emplace_back(
            umfPoolMalloc(pool.get(), allocSize),
            [pool = pool.get()](void *ptr) { umfPoolFree(pool, ptr); });
    }
}
