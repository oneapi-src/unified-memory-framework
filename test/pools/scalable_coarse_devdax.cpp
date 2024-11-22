// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "umf/pools/pool_scalable.h"
#include "umf/providers/provider_devdax_memory.h"

#include "pool_coarse.hpp"

using devdax_params_unique_handle_t =
    std::unique_ptr<umf_devdax_memory_provider_params_t,
                    decltype(&umfDevDaxMemoryProviderParamsDestroy)>;

devdax_params_unique_handle_t create_devdax_params() {
    char *path = getenv("UMF_TESTS_DEVDAX_PATH");
    char *size = getenv("UMF_TESTS_DEVDAX_SIZE");
    if (path == nullptr || path[0] == 0 || size == nullptr || size[0] == 0) {
        return devdax_params_unique_handle_t(
            nullptr, &umfDevDaxMemoryProviderParamsDestroy);
    }

    umf_devdax_memory_provider_params_handle_t params = NULL;
    umf_result_t res =
        umfDevDaxMemoryProviderParamsCreate(&params, path, atol(size));
    if (res != UMF_RESULT_SUCCESS) {
        throw std::runtime_error(
            "Failed to create DevDax Memory Provider params");
    }

    return devdax_params_unique_handle_t(params,
                                         &umfDevDaxMemoryProviderParamsDestroy);
}

auto coarseParams = umfCoarseMemoryProviderParamsDefault();
auto devdaxParams = create_devdax_params();

static std::vector<poolCreateExtParams> poolParamsList =
    devdaxParams.get()
        ? std::vector<poolCreateExtParams>{poolCreateExtParams{
              umfScalablePoolOps(), nullptr, umfDevDaxMemoryProviderOps(),
              devdaxParams.get(), &coarseParams}}
        : std::vector<poolCreateExtParams>{};

INSTANTIATE_TEST_SUITE_P(scalableCoarseDevDaxTest, umfPoolTest,
                         ::testing::ValuesIn(poolParamsList));
