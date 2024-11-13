// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <umf/memory_provider.h>
#include <umf/providers/provider_file_memory.h>
#ifdef UMF_POOL_JEMALLOC_ENABLED
#include <umf/pools/pool_jemalloc.h>
#endif
#ifdef UMF_POOL_SCALABLE_ENABLED
#include <umf/pools/pool_scalable.h>
#endif

#include "ipcFixtures.hpp"

using umf_test::test;

#define FILE_PATH ((char *)"tmp_file")

umf_file_memory_provider_params_t get_file_params_shared(char *path) {
    umf_file_memory_provider_params_t file_params =
        umfFileMemoryProviderParamsDefault(path);
    file_params.visibility = UMF_MEM_MAP_SHARED;
    return file_params;
}

umf_file_memory_provider_params_t file_params_shared =
    get_file_params_shared(FILE_PATH);

umf_file_memory_provider_params_t get_file_params_fsdax(char *path) {
    umf_file_memory_provider_params_t file_params =
        umfFileMemoryProviderParamsDefault(path);
    file_params.visibility = UMF_MEM_MAP_SHARED;
    return file_params;
}

umf_file_memory_provider_params_t file_params_fsdax =
    get_file_params_fsdax(getenv("UMF_TESTS_FSDAX_PATH"));

HostMemoryAccessor hostAccessor;

static std::vector<ipcTestParams> ipcManyPoolsTestParamsList = {
// TODO: enable it when sizes of allocations in ipcFixtures.hpp are fixed
//    {umfProxyPoolOps(), nullptr, umfFileMemoryProviderOps(),
//     &file_params_shared, &hostAccessor, true},
#ifdef UMF_POOL_JEMALLOC_ENABLED
    {umfJemallocPoolOps(), nullptr, umfFileMemoryProviderOps(),
     &file_params_shared, &hostAccessor, false},
#endif
#ifdef UMF_POOL_SCALABLE_ENABLED
    {umfScalablePoolOps(), nullptr, umfFileMemoryProviderOps(),
     &file_params_shared, &hostAccessor, false},
#endif
};

static std::vector<ipcTestParams> getIpcFsDaxTestParamsList(void) {
    std::vector<ipcTestParams> ipcFsDaxTestParamsList = {};

    char *path = getenv("UMF_TESTS_FSDAX_PATH");
    if (path == nullptr || path[0] == 0) {
        // skipping the test, UMF_TESTS_FSDAX_PATH is not set
        return ipcFsDaxTestParamsList;
    }

    ipcFsDaxTestParamsList = {
// TODO: enable it when sizes of allocations in ipcFixtures.hpp are fixed
//        {umfProxyPoolOps(), nullptr, umfFileMemoryProviderOps(),
//         &file_params_fsdax, &hostAccessor, true},
#ifdef UMF_POOL_JEMALLOC_ENABLED
        {umfJemallocPoolOps(), nullptr, umfFileMemoryProviderOps(),
         &file_params_fsdax, &hostAccessor, false},
#endif
#ifdef UMF_POOL_SCALABLE_ENABLED
        {umfScalablePoolOps(), nullptr, umfFileMemoryProviderOps(),
         &file_params_fsdax, &hostAccessor, false},
#endif
    };

    return ipcFsDaxTestParamsList;
}

GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfIpcTest);

INSTANTIATE_TEST_SUITE_P(FileProviderDifferentPoolsTest, umfIpcTest,
                         ::testing::ValuesIn(ipcManyPoolsTestParamsList));

INSTANTIATE_TEST_SUITE_P(FileProviderDifferentPoolsFSDAXTest, umfIpcTest,
                         ::testing::ValuesIn(getIpcFsDaxTestParamsList()));
