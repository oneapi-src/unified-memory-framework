// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "base.hpp"

#include <umf/providers/provider_os_memory.h>

using umf_test::test;

TEST_F(test, os_provider_not_implemented) {
    umf_os_memory_provider_params_handle_t params = nullptr;
    umf_result_t umf_result = umfOsMemoryProviderParamsCreate(&params);
    EXPECT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);
    EXPECT_EQ(params, nullptr);

    umf_result = umfOsMemoryProviderParamsDestroy(params);
    EXPECT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    umf_result = umfOsMemoryProviderParamsSetProtection(params, 0);
    EXPECT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    umf_result =
        umfOsMemoryProviderParamsSetVisibility(params, UMF_MEM_MAP_PRIVATE);
    EXPECT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    umf_result = umfOsMemoryProviderParamsSetShmName(params, "shm_name");
    EXPECT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    umf_result = umfOsMemoryProviderParamsSetNumaList(params, nullptr, 0);
    EXPECT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    umf_result =
        umfOsMemoryProviderParamsSetNumaMode(params, UMF_NUMA_MODE_DEFAULT);
    EXPECT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    umf_result = umfOsMemoryProviderParamsSetPartSize(params, 4096);
    EXPECT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    umf_numa_split_partition_t partitions[1];
    umf_result = umfOsMemoryProviderParamsSetPartitions(params, partitions, 1);
    EXPECT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    umf_memory_provider_ops_t *ops = umfOsMemoryProviderOps();
    EXPECT_EQ(ops, nullptr);
}
