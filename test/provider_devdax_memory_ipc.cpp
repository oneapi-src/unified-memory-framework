// Copyright (C) 2024-2025 Intel Corporation
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

bool devDaxEnvSet() {
    char *path = getenv("UMF_TESTS_DEVDAX_PATH");
    char *size = getenv("UMF_TESTS_DEVDAX_SIZE");
    if (path == nullptr || path[0] == 0 || size == nullptr || size[0] == 0) {
        return false;
    }

    return true;
}

void *defaultDevDaxParamsCreate() {
    char *path = getenv("UMF_TESTS_DEVDAX_PATH");
    char *size = getenv("UMF_TESTS_DEVDAX_SIZE");
    if (path == nullptr || path[0] == 0 || size == nullptr || size[0] == 0) {
        return nullptr;
    }

    umf_devdax_memory_provider_params_handle_t params = NULL;
    umf_result_t res =
        umfDevDaxMemoryProviderParamsCreate(&params, path, atol(size));
    if (res != UMF_RESULT_SUCCESS) {
        throw std::runtime_error(
            "Failed to create DevDax Memory Provider params");
    }

    return params;
}

umf_result_t defaultDevDaxParamsDestroy(void *params) {
    return umfDevDaxMemoryProviderParamsDestroy(
        (umf_devdax_memory_provider_params_handle_t)params);
}

HostMemoryAccessor hostAccessor;

static std::vector<ipcTestParams> getIpcProxyPoolTestParamsList(void) {
    std::vector<ipcTestParams> ipcProxyPoolTestParamsList = {};

    if (!devDaxEnvSet()) {
        // return empty list to skip the test
        return ipcProxyPoolTestParamsList;
    }

    ipcProxyPoolTestParamsList = {
        {umfProxyPoolOps(), nullptr, nullptr, umfDevDaxMemoryProviderOps(),
         defaultDevDaxParamsCreate, defaultDevDaxParamsDestroy, &hostAccessor},
#ifdef UMF_POOL_JEMALLOC_ENABLED
        {umfJemallocPoolOps(), nullptr, nullptr, umfDevDaxMemoryProviderOps(),
         defaultDevDaxParamsCreate, defaultDevDaxParamsDestroy, &hostAccessor},
#endif
#ifdef UMF_POOL_SCALABLE_ENABLED
        {umfScalablePoolOps(), nullptr, nullptr, umfDevDaxMemoryProviderOps(),
         defaultDevDaxParamsCreate, defaultDevDaxParamsDestroy, &hostAccessor},
#endif
    };

    return ipcProxyPoolTestParamsList;
}

GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfIpcTest);

INSTANTIATE_TEST_SUITE_P(DevDaxProviderDifferentPoolsTest, umfIpcTest,
                         ::testing::ValuesIn(getIpcProxyPoolTestParamsList()));
