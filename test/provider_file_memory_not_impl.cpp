// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "base.hpp"

#include <umf/providers/provider_file_memory.h>

using umf_test::test;

TEST_F(test, file_provider_not_implemented) {
    umf_file_memory_provider_params_handle_t params = nullptr;
    umf_result_t umf_result =
        umfFileMemoryProviderParamsCreate(&params, "path");
    EXPECT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);
    EXPECT_EQ(params, nullptr);

    umf_result = umfFileMemoryProviderParamsDestroy(nullptr);
    EXPECT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    umf_result = umfFileMemoryProviderParamsSetPath(nullptr, "path");
    EXPECT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    umf_result = umfFileMemoryProviderParamsSetProtection(nullptr, 0);
    EXPECT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    umf_result =
        umfFileMemoryProviderParamsSetVisibility(nullptr, UMF_MEM_MAP_PRIVATE);
    EXPECT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    umf_memory_provider_ops_t *ops = umfFileMemoryProviderOps();
    EXPECT_EQ(ops, nullptr);
}