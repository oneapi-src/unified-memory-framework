// Copyright (C) 2023-2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <stdlib.h>

#include <umf/pools/pool_disjoint.h>

#include "provider_null.h"
#include "test_helpers.h"
#include "test_ut_asserts.h"

void test_disjoint_pool_default_params(void) {
    umf_memory_provider_handle_t provider = nullProviderCreate();
    umf_result_t retp;
    umf_memory_pool_handle_t pool = NULL;
    umf_disjoint_pool_params_handle_t params = NULL;

    retp = umfDisjointPoolParamsCreate(&params);
    UT_ASSERTeq(retp, UMF_RESULT_SUCCESS);

    retp = umfPoolCreate(umfDisjointPoolOps(), provider, params, 0, &pool);
    UT_ASSERTeq(retp, UMF_RESULT_SUCCESS);

    umfPoolDestroy(pool);
    umfDisjointPoolParamsDestroy(params);
    umfMemoryProviderDestroy(provider);
}

void test_disjoint_pool_shared_limits(void) {
    umf_memory_provider_handle_t provider = nullProviderCreate();
    umf_result_t retp;
    umf_memory_pool_handle_t pool = NULL;
    umf_disjoint_pool_params_handle_t params = NULL;

    retp = umfDisjointPoolParamsCreate(&params);
    UT_ASSERTeq(retp, UMF_RESULT_SUCCESS);

    umf_disjoint_pool_shared_limits_handle_t limits =
        umfDisjointPoolSharedLimitsCreate(1024);
    UT_ASSERTne(limits, NULL);

    retp = umfDisjointPoolParamsSetSharedLimits(params, limits);
    UT_ASSERTeq(retp, UMF_RESULT_SUCCESS);

    retp = umfPoolCreate(umfDisjointPoolOps(), provider, &params, 0, &pool);
    UT_ASSERTeq(retp, UMF_RESULT_SUCCESS);

    umfPoolDestroy(pool);
    umfMemoryProviderDestroy(provider);
    umfDisjointPoolSharedLimitsDestroy(limits);
    umfDisjointPoolParamsDestroy(params);
}

int main(void) {
    test_disjoint_pool_default_params();
    return 0;
}
