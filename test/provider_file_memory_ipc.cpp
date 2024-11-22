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

using file_params_unique_handle_t =
    std::unique_ptr<umf_file_memory_provider_params_t,
                    decltype(&umfFileMemoryProviderParamsDestroy)>;

file_params_unique_handle_t get_file_params_shared(char *path) {
    umf_file_memory_provider_params_handle_t file_params = NULL;
    umf_result_t res = umfFileMemoryProviderParamsCreate(&file_params, path);
    if (res != UMF_RESULT_SUCCESS) {
        throw std::runtime_error(
            "Failed to create File Memory Provider params");
    }

    res = umfFileMemoryProviderParamsSetVisibility(file_params,
                                                   UMF_MEM_MAP_SHARED);
    if (res != UMF_RESULT_SUCCESS) {
        umfFileMemoryProviderParamsDestroy(file_params);
        throw std::runtime_error("Failed to set visibility to shared for File "
                                 "Memory Provider params");
    }

    return file_params_unique_handle_t(file_params,
                                       &umfFileMemoryProviderParamsDestroy);
}

file_params_unique_handle_t file_params_shared =
    get_file_params_shared(FILE_PATH);

file_params_unique_handle_t get_file_params_fsdax(char *path) {
    umf_file_memory_provider_params_handle_t file_params = NULL;
    umf_result_t res = umfFileMemoryProviderParamsCreate(&file_params, path);
    if (res != UMF_RESULT_SUCCESS) {
        //test will be skipped.
        return file_params_unique_handle_t(nullptr,
                                           &umfFileMemoryProviderParamsDestroy);
    }

    res = umfFileMemoryProviderParamsSetVisibility(file_params,
                                                   UMF_MEM_MAP_SHARED);
    if (res != UMF_RESULT_SUCCESS) {
        umfFileMemoryProviderParamsDestroy(file_params);
        throw std::runtime_error("Failed to set visibility to shared for File "
                                 "Memory Provider params");
    }

    return file_params_unique_handle_t(file_params,
                                       &umfFileMemoryProviderParamsDestroy);
}

file_params_unique_handle_t file_params_fsdax =
    get_file_params_fsdax(getenv("UMF_TESTS_FSDAX_PATH"));

HostMemoryAccessor hostAccessor;

static std::vector<ipcTestParams> ipcManyPoolsTestParamsList = {
// TODO: enable it when sizes of allocations in ipcFixtures.hpp are fixed
//    {umfProxyPoolOps(), nullptr, umfFileMemoryProviderOps(),
//     file_params_shared.get(), &hostAccessor, true},
#ifdef UMF_POOL_JEMALLOC_ENABLED
    {umfJemallocPoolOps(), nullptr, umfFileMemoryProviderOps(),
     file_params_shared.get(), &hostAccessor, false},
#endif
#ifdef UMF_POOL_SCALABLE_ENABLED
    {umfScalablePoolOps(), nullptr, umfFileMemoryProviderOps(),
     file_params_shared.get(), &hostAccessor, false},
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
//         file_params_fsdax.get(), &hostAccessor, true},
#ifdef UMF_POOL_JEMALLOC_ENABLED
        {umfJemallocPoolOps(), nullptr, umfFileMemoryProviderOps(),
         file_params_fsdax.get(), &hostAccessor, false},
#endif
#ifdef UMF_POOL_SCALABLE_ENABLED
        {umfScalablePoolOps(), nullptr, umfFileMemoryProviderOps(),
         file_params_fsdax.get(), &hostAccessor, false},
#endif
    };

    return ipcFsDaxTestParamsList;
}

GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfIpcTest);

INSTANTIATE_TEST_SUITE_P(FileProviderDifferentPoolsTest, umfIpcTest,
                         ::testing::ValuesIn(ipcManyPoolsTestParamsList));

INSTANTIATE_TEST_SUITE_P(FileProviderDifferentPoolsFSDAXTest, umfIpcTest,
                         ::testing::ValuesIn(getIpcFsDaxTestParamsList()));
