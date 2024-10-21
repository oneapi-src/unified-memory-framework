// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "umf/pools/pool_scalable.h"

#include "pool_coarse_file.hpp"

auto coarseParams = umfCoarseMemoryProviderParamsDefault();
auto fileParams = umfFileMemoryProviderParamsDefault(FILE_PATH);

INSTANTIATE_TEST_SUITE_P(scalableCoarseFileTest, umfPoolTest,
                         ::testing::Values(poolCreateExtParams{
                             umfScalablePoolOps(), nullptr,
                             umfFileMemoryProviderOps(), &fileParams,
                             &coarseParams}));
