// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "umf/pools/pool_scalable.h"
#include "umf/providers/provider_file_memory.h"

#include "pool_coarse.hpp"

using file_params_unique_handle_t =
    std::unique_ptr<umf_file_memory_provider_params_t,
                    decltype(&umfFileMemoryProviderParamsDestroy)>;

file_params_unique_handle_t get_file_params_default(char *path) {
    umf_file_memory_provider_params_handle_t file_params = NULL;
    umf_result_t res = umfFileMemoryProviderParamsCreate(&file_params, path);
    if (res != UMF_RESULT_SUCCESS) {
        throw std::runtime_error(
            "Failed to create File Memory Provider params");
    }

    return file_params_unique_handle_t(file_params,
                                       &umfFileMemoryProviderParamsDestroy);
}

auto coarseParams = umfCoarseMemoryProviderParamsDefault();
file_params_unique_handle_t fileParams = get_file_params_default(FILE_PATH);

INSTANTIATE_TEST_SUITE_P(scalableCoarseFileTest, umfPoolTest,
                         ::testing::Values(poolCreateExtParams{
                             umfScalablePoolOps(), nullptr,
                             umfFileMemoryProviderOps(), fileParams.get(),
                             &coarseParams}));
