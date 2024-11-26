// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "base.hpp"

#include <umf/providers/provider_devdax_memory.h>

using umf_test::test;

TEST_F(test, devdax_provider_not_implemented) {
    umf_devdax_memory_provider_params_handle_t params = nullptr;
    umf_result_t umf_result =
        umfDevDaxMemoryProviderParamsCreate(&params, "path", 4096);
    EXPECT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);
    EXPECT_EQ(params, nullptr);

    umf_result = umfDevDaxMemoryProviderParamsDestroy(nullptr);
    EXPECT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    umf_result =
        umfDevDaxMemoryProviderParamsSetDeviceDax(nullptr, "path", 4096);
    EXPECT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    umf_result = umfDevDaxMemoryProviderParamsSetProtection(nullptr, 0);
    EXPECT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    umf_memory_provider_ops_t *ops = umfDevDaxMemoryProviderOps();
    EXPECT_EQ(ops, nullptr);
}
