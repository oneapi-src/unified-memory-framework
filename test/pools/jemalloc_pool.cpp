// Copyright (C) 2023 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "umf/pools/pool_jemalloc.h"
#include "umf/providers/provider_os_memory.h"

#include "pool.hpp"
#include "poolFixtures.hpp"

static umf_os_memory_provider_params_t UMF_OS_MEMORY_PROVIDER_PARAMS = {
    /* .protection = */ UMF_PROTECTION_READ | UMF_PROTECTION_WRITE,
    /* .visibility = */ UMF_VISIBILITY_PRIVATE,

    // NUMA config
    /* .nodemask = */ NULL,
    /* .maxnode = */ 0,
    /* .numa_mode = */ UMF_NUMA_MODE_DEFAULT,
    /* .numa_flags = */ 0,

    // others
    /* .traces = */ 0,
};

using umf_test::test;
using namespace umf_test;

TEST_F(test, metadataUseProvider) {
    size_t allocSize = 1024;
    umf_jemalloc_pool_params_t metadataByMallocParams;
    metadataByMallocParams.metadata_use_provider = false;

    umf_jemalloc_pool_params_t metadataByProviderParams;
    metadataByProviderParams.metadata_use_provider = true;

    static size_t numAllocs = 0;
    struct memory_provider : public umf_test::provider_base_t {
        umf_result_t alloc(size_t size, size_t, void **ptr) noexcept {
            *ptr = malloc(size);
            numAllocs++;
            return UMF_RESULT_SUCCESS;
        }
        umf_result_t free(void *ptr, [[maybe_unused]] size_t size) noexcept {
            ::free(ptr);
            return UMF_RESULT_SUCCESS;
        }
    };
    umf_memory_provider_ops_t provider_ops =
        umf::providerMakeCOps<memory_provider, void>();

    umf_result_t res = UMF_RESULT_ERROR_UNKNOWN;
    umf::pool_unique_handle_t poolMetadataByMalloc;
    try {
        poolMetadataByMalloc =
            poolCreateExt<ErrorReportingStrategyType::Exception>(
                {&UMF_JEMALLOC_POOL_OPS, (void *)&metadataByMallocParams,
                 &provider_ops, nullptr});
        res = UMF_RESULT_SUCCESS;
    } catch (umf_result_t &status) {
        res = status;
    }

    if (res == UMF_RESULT_ERROR_NOT_SUPPORTED) {
        GTEST_SKIP() << "Wrong version of jemalloc";
    }
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);

    auto *ptr1 = umfPoolMalloc(poolMetadataByMalloc.get(), allocSize);
    auto numAllocsPoolMetadataByMalloc = numAllocs;

    numAllocs = 0;

    auto poolMetadataByProvider = poolCreateExt(
        {&UMF_JEMALLOC_POOL_OPS, (void *)&metadataByProviderParams,
         &provider_ops, nullptr});
    auto *ptr2 = umfPoolMalloc(poolMetadataByProvider.get(), allocSize);

    ASSERT_GT(numAllocs, numAllocsPoolMetadataByMalloc);

    umfFree(ptr1);
    umfFree(ptr2);
}

INSTANTIATE_TEST_SUITE_P(jemallocPoolTest, umfPoolTest,
                         ::testing::Values(poolCreateExtParams{
                             &UMF_JEMALLOC_POOL_OPS, nullptr,
                             &UMF_OS_MEMORY_PROVIDER_OPS,
                             &UMF_OS_MEMORY_PROVIDER_PARAMS}));
