// Copyright (C) 2023 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "umf/pools/pool_scalable.h"
#include "umf/providers/provider_os_memory.h"

#include "pool.hpp"
#include "poolFixtures.hpp"

auto defaultParams = umfOsMemoryProviderParamsDefault();
INSTANTIATE_TEST_SUITE_P(scalablePoolTest, umfPoolTest,
                         ::testing::Values(poolCreateExtParams{
                             umfScalablePoolOps(), nullptr,
                             umfOsMemoryProviderOps(), &defaultParams,
                             nullptr}));
