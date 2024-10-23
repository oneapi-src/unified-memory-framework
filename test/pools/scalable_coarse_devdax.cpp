// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "umf/pools/pool_scalable.h"
#include "umf/providers/provider_devdax_memory.h"

#include "pool_coarse.hpp"

auto coarseParams = umfCoarseMemoryProviderParamsDefault();
auto devdaxParams = umfDevDaxMemoryProviderParamsDefault(
    getenv("UMF_TESTS_DEVDAX_PATH"), getenv("UMF_TESTS_DEVDAX_SIZE")
                                         ? atol(getenv("UMF_TESTS_DEVDAX_SIZE"))
                                         : 0);

INSTANTIATE_TEST_SUITE_P(scalableCoarseDevDaxTest, umfPoolTest,
                         ::testing::Values(poolCreateExtParams{
                             umfScalablePoolOps(), nullptr,
                             umfDevDaxMemoryProviderOps(), &devdaxParams,
                             &coarseParams}));
