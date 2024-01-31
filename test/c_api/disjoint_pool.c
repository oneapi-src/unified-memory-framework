// Copyright (C) 2023-2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <stdlib.h>

#include "pool_disjoint.h"
#include "provider_null.h"
#include "test_helpers.h"

void test_disjoint_pool_default_params(void) {
    umf_memory_provider_handle_t provider = nullProviderCreate();
    umf_result_t retp;
    umf_memory_pool_handle_t pool = NULL;
    umf_disjoint_pool_params_t params = umfDisjointPoolParamsDefault();
    retp = umfPoolCreate(umfDisjointPoolOps(), provider, &params, 0, &pool);

    UT_ASSERTeq(retp, UMF_RESULT_SUCCESS);

    umfPoolDestroy(pool);
    umfMemoryProviderDestroy(provider);
}

void test_disjoint_pool_shared_limits(void) {
    umf_memory_provider_handle_t provider = nullProviderCreate();
    umf_result_t retp;
    umf_memory_pool_handle_t pool = NULL;
    umf_disjoint_pool_params_t params = umfDisjointPoolParamsDefault();

    umf_disjoint_pool_shared_limits_t *limits =
        umfDisjointPoolSharedLimitsCreate(1024);
    params.SharedLimits = limits;

    retp = umfPoolCreate(umfDisjointPoolOps(), provider, &params, 0, &pool);

    UT_ASSERTeq(retp, UMF_RESULT_SUCCESS);

    umfPoolDestroy(pool);
    umfMemoryProviderDestroy(provider);
    umfDisjointPoolSharedLimitsDestroy(limits);
}

int main(void) {
    test_disjoint_pool_default_params();
    return 0;
}
