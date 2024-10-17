// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "umf/pools/pool_jemalloc.h"
#include "umf/pools/pool_scalable.h"
#include "umf/providers/provider_coarse.h"
#include "umf/providers/provider_file_memory.h"

#include "pool.hpp"
#include "poolFixtures.hpp"

using umf_test::test;
using namespace umf_test;

#define INIT_BUFFER_SIZE 4096
#define FILE_PATH ((char *)"/tmp/file_provider")

coarse_memory_provider_params_t getCoarseParams(size_t init_buffer_size) {
    coarse_memory_provider_params_t coarse_memory_provider_params;

    // make sure there are no undefined members - prevent a UB
    memset(&coarse_memory_provider_params, 0,
           sizeof(coarse_memory_provider_params));

    // upstream_memory_provider will be set later in umfPoolTest
    coarse_memory_provider_params.upstream_memory_provider = nullptr;
    coarse_memory_provider_params.immediate_init_from_upstream = true;
    coarse_memory_provider_params.init_buffer = nullptr;
    coarse_memory_provider_params.init_buffer_size = init_buffer_size;

    return coarse_memory_provider_params;
}

auto coarseParams = getCoarseParams(INIT_BUFFER_SIZE);
auto fileParams = umfFileMemoryProviderParamsDefault(FILE_PATH);

INSTANTIATE_TEST_SUITE_P(jemallocCoarseFileTest, umfPoolTest,
                         ::testing::Values(poolCreateExtParams{
                             umfJemallocPoolOps(), nullptr,
                             umfFileMemoryProviderOps(), &fileParams,
                             &coarseParams}));

INSTANTIATE_TEST_SUITE_P(scalableCoarseFileTest, umfPoolTest,
                         ::testing::Values(poolCreateExtParams{
                             umfScalablePoolOps(), nullptr,
                             umfFileMemoryProviderOps(), &fileParams,
                             &coarseParams}));
