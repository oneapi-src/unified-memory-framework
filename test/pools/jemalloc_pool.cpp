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

INSTANTIATE_TEST_SUITE_P(jemallocPoolTest, umfPoolTest,
                         ::testing::Values(poolCreateExtParams{
                             &UMF_JEMALLOC_POOL_OPS, nullptr,
                             &UMF_OS_MEMORY_PROVIDER_OPS,
                             &UMF_OS_MEMORY_PROVIDER_PARAMS}));
