// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <umf/memory_provider.h>
#include <umf/providers/provider_devdax_memory.h>
#ifdef UMF_POOL_JEMALLOC_ENABLED
#include <umf/pools/pool_jemalloc.h>
#endif
#ifdef UMF_POOL_SCALABLE_ENABLED
#include <umf/pools/pool_scalable.h>
#endif

#include "ipcFixtures.hpp"

using umf_test::test;

auto defaultDevDaxParams = umfDevDaxMemoryProviderParamsDefault(
    getenv("UMF_TESTS_DEVDAX_PATH"),
    atol(getenv("UMF_TESTS_DEVDAX_SIZE") ? getenv("UMF_TESTS_DEVDAX_SIZE")
                                         : "0"));

HostMemoryAccessor hostAccessor;

static std::vector<ipcTestParams> getIpcProxyPoolTestParamsList(void) {
    std::vector<ipcTestParams> ipcProxyPoolTestParamsList = {};

    char *path = getenv("UMF_TESTS_DEVDAX_PATH");
    if (path == nullptr || path[0] == 0) {
        // skipping the test, UMF_TESTS_DEVDAX_PATH is not set
        return ipcProxyPoolTestParamsList;
    }

    char *size = getenv("UMF_TESTS_DEVDAX_SIZE");
    if (size == nullptr || size[0] == 0) {
        // skipping the test, UMF_TESTS_DEVDAX_SIZE is not set
        return ipcProxyPoolTestParamsList;
    }

    ipcProxyPoolTestParamsList = {
        {umfProxyPoolOps(), nullptr, umfDevDaxMemoryProviderOps(),
         &defaultDevDaxParams, &hostAccessor, true},
#ifdef UMF_POOL_JEMALLOC_ENABLED
        {umfJemallocPoolOps(), nullptr, umfDevDaxMemoryProviderOps(),
         &defaultDevDaxParams, &hostAccessor, false},
#endif
#ifdef UMF_POOL_SCALABLE_ENABLED
        {umfScalablePoolOps(), nullptr, umfDevDaxMemoryProviderOps(),
         &defaultDevDaxParams, &hostAccessor, false},
#endif
    };

    return ipcProxyPoolTestParamsList;
}

GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfIpcTest);

INSTANTIATE_TEST_SUITE_P(DevDaxProviderDifferentPoolsTest, umfIpcTest,
                         ::testing::ValuesIn(getIpcProxyPoolTestParamsList()));
