// Copyright (C) 2024-2025 Intel Corporation
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

void *createFileParamsShared() {
    umf_file_memory_provider_params_handle_t file_params = NULL;
    umf_result_t res =
        umfFileMemoryProviderParamsCreate(&file_params, FILE_PATH);
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

    return file_params;
}

umf_result_t destroyFileParamsShared(void *params) {
    return umfFileMemoryProviderParamsDestroy(
        (umf_file_memory_provider_params_handle_t)params);
}

void *createFileParamsFSDAX() {
    umf_file_memory_provider_params_handle_t file_params = NULL;
    umf_result_t res = umfFileMemoryProviderParamsCreate(
        &file_params, getenv("UMF_TESTS_FSDAX_PATH"));
    if (res != UMF_RESULT_SUCCESS) {
        //test will be skipped.
        return nullptr;
    }

    res = umfFileMemoryProviderParamsSetVisibility(file_params,
                                                   UMF_MEM_MAP_SHARED);
    if (res != UMF_RESULT_SUCCESS) {
        umfFileMemoryProviderParamsDestroy(file_params);
        throw std::runtime_error("Failed to set visibility to shared for File "
                                 "Memory Provider params");
    }

    return file_params;
}

umf_result_t destroyFileParamsFSDAX(void *params) {
    return umfFileMemoryProviderParamsDestroy(
        (umf_file_memory_provider_params_handle_t)params);
}

#ifdef UMF_POOL_JEMALLOC_ENABLED
void *createJemallocParams() {
    umf_jemalloc_pool_params_handle_t jemalloc_params = NULL;
    umf_result_t res = umfJemallocPoolParamsCreate(&jemalloc_params);
    if (res != UMF_RESULT_SUCCESS) {
        throw std::runtime_error("Failed to create Jemalloc Pool params");
    }

    // This test creates multiple pools, so we need to reduce the number of arenas
    // to avoid hitting the maximum arena limit on systems with many cores.
    res = umfJemallocPoolParamsSetNumArenas(jemalloc_params, 1);
    if (res != UMF_RESULT_SUCCESS) {
        umfJemallocPoolParamsDestroy(jemalloc_params);
        throw std::runtime_error("Failed to set number of arenas for Jemalloc "
                                 "Pool params");
    }
    return jemalloc_params;
}

umf_result_t destroyJemallocParams(void *params) {
    return umfJemallocPoolParamsDestroy(
        (umf_jemalloc_pool_params_handle_t)params);
}

#endif

HostMemoryAccessor hostAccessor;

static std::vector<ipcTestParams> ipcManyPoolsTestParamsList = {
// TODO: enable it when sizes of allocations in ipcFixtures.hpp are fixed
//    {umfProxyPoolOps(), nullptr, umfFileMemoryProviderOps(),
//     file_params_shared.get(), &hostAccessor},
#ifdef UMF_POOL_JEMALLOC_ENABLED
    {umfJemallocPoolOps(), createJemallocParams, destroyJemallocParams,
     umfFileMemoryProviderOps(), createFileParamsShared,
     destroyFileParamsShared, &hostAccessor},
#endif
#ifdef UMF_POOL_SCALABLE_ENABLED
    {umfScalablePoolOps(), nullptr, nullptr, umfFileMemoryProviderOps(),
     createFileParamsShared, destroyFileParamsShared, &hostAccessor},
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
//         file_params_fsdax.get(), &hostAccessor},
#ifdef UMF_POOL_JEMALLOC_ENABLED
        {umfJemallocPoolOps(), createJemallocParams, destroyJemallocParams,
         umfFileMemoryProviderOps(), createFileParamsFSDAX,
         destroyFileParamsFSDAX, &hostAccessor},
#endif
#ifdef UMF_POOL_SCALABLE_ENABLED
        {umfScalablePoolOps(), nullptr, nullptr, umfFileMemoryProviderOps(),
         createFileParamsFSDAX, destroyFileParamsFSDAX, &hostAccessor},
#endif
    };

    return ipcFsDaxTestParamsList;
}

GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfIpcTest);

INSTANTIATE_TEST_SUITE_P(FileProviderDifferentPoolsTest, umfIpcTest,
                         ::testing::ValuesIn(ipcManyPoolsTestParamsList));

INSTANTIATE_TEST_SUITE_P(FileProviderDifferentPoolsFSDAXTest, umfIpcTest,
                         ::testing::ValuesIn(getIpcFsDaxTestParamsList()));
