// Copyright (C) 2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exceptiongi

#include <umf/memory_pool.h>
#include <umf/pools/pool_disjoint.h>

#include "base.hpp"
#include <umf/memory_pool.h>
#include <umf/memory_provider.h>
#include <umf/memory_provider_ops.h>
#include <umf/providers/provider_os_memory.h>

using umf_test::test;
using namespace umf_test;

TEST_F(test, disjointCtlName) {
    umf_memory_provider_handle_t hProvider = NULL;
    umf_os_memory_provider_params_handle_t os_memory_provider_params = NULL;
    umf_memory_provider_ops_t *os_provider_ops = umfOsMemoryProviderOps();
    if (os_provider_ops == NULL) {
        GTEST_SKIP() << "OS memory provider is not supported!";
    }

    int ret = umfOsMemoryProviderParamsCreate(&os_memory_provider_params);
    ret = umfMemoryProviderCreate(os_provider_ops, os_memory_provider_params,
                                  &hProvider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    const char *val = "disjoint_new_name";
    umfCtlSet("umf.pool.default.disjoint.name", NULL, (void *)val, strlen(val));

    umf_memory_pool_handle_t hPool;
    umf_disjoint_pool_params_handle_t params;
    umfDisjointPoolParamsCreate(&params);
    umfPoolCreate(umfDisjointPoolOps(), hProvider, params, 0, &hPool);
    ASSERT_STREQ(umfPoolGetName(hPool), val);

    // Clean up
    umfDisjointPoolParamsDestroy(params);
    umfOsMemoryProviderParamsDestroy(os_memory_provider_params);
    umfPoolDestroy(hPool);
    umfMemoryProviderDestroy(hProvider);
}
