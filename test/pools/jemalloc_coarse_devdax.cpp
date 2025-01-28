// Copyright (C) 2024-2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "umf/pools/pool_jemalloc.h"
#include "umf/providers/provider_devdax_memory.h"

#include "pool_coarse.hpp"

bool devDaxEnvSet() {
    char *path = getenv("UMF_TESTS_DEVDAX_PATH");
    char *size = getenv("UMF_TESTS_DEVDAX_SIZE");
    if (path == nullptr || path[0] == 0 || size == nullptr || size[0] == 0) {
        return false;
    }

    return true;
}

void *createDevDaxParams() {
    char *path = getenv("UMF_TESTS_DEVDAX_PATH");
    char *size = getenv("UMF_TESTS_DEVDAX_SIZE");

    umf_devdax_memory_provider_params_handle_t params = NULL;
    umf_result_t res =
        umfDevDaxMemoryProviderParamsCreate(&params, path, atol(size));
    if (res != UMF_RESULT_SUCCESS) {
        throw std::runtime_error(
            "Failed to create DevDax Memory Provider params");
    }

    return params;
}

static std::vector<poolCreateExtParams> poolParamsList =
    devDaxEnvSet()
        ? std::vector<poolCreateExtParams>{poolCreateExtParams{
              umfJemallocPoolOps(), nullptr, nullptr,
              umfDevDaxMemoryProviderOps(), createDevDaxParams,
              (pfnProviderParamsDestroy)umfDevDaxMemoryProviderParamsDestroy}}
        : std::vector<poolCreateExtParams>{};

INSTANTIATE_TEST_SUITE_P(jemallocCoarseDevDaxTest, umfPoolTest,
                         ::testing::ValuesIn(poolParamsList));
