// Copyright (C) 2023-2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <stdlib.h>

#include <umf/memory_pool.h>
#include <umf/pools/pool_disjoint.h>
#include <umf/pools/pool_jemalloc.h>
#include <umf/pools/pool_proxy.h>
#include <umf/pools/pool_scalable.h>
#include <umf/providers/provider_os_memory.h>

#include "test_helpers.h"

umf_memory_pool_handle_t
createDisjointPool(umf_memory_provider_handle_t provider) {
    umf_memory_pool_handle_t pool = NULL;
    umf_disjoint_pool_params_t params = umfDisjointPoolParamsDefault();
    umf_result_t ret =
        umfPoolCreate(umfDisjointPoolOps(), provider, &params, 0, &pool);
    UT_ASSERTeq(ret, UMF_RESULT_SUCCESS);
    return pool;
}

umf_memory_pool_handle_t
createProxyPool(umf_memory_provider_handle_t provider) {
    umf_memory_pool_handle_t pool = NULL;
    umf_result_t ret =
        umfPoolCreate(umfProxyPoolOps(), provider, NULL, 0, &pool);
    UT_ASSERTeq(ret, UMF_RESULT_SUCCESS);
    return pool;
}

umf_memory_pool_handle_t
createJemallocPool(umf_memory_provider_handle_t provider) {
    umf_memory_pool_handle_t pool = NULL;
    umf_result_t ret =
        umfPoolCreate(umfJemallocPoolOps(), provider, NULL, 0, &pool);
    UT_ASSERTeq(ret, UMF_RESULT_SUCCESS);
    return pool;
}

umf_memory_pool_handle_t
createScalablePool(umf_memory_provider_handle_t provider) {
    umf_memory_pool_handle_t pool = NULL;
    umf_result_t ret =
        umfPoolCreate(umfScalablePoolOps(), provider, NULL, 0, &pool);
    UT_ASSERTeq(ret, UMF_RESULT_SUCCESS);
    return pool;
}

#define ALLOC_SIZE 64

int main(void) {
    umf_os_memory_provider_params_t params = umfOsMemoryProviderParamsDefault();

    umf_memory_provider_handle_t hProvider;
    umf_result_t ret =
        umfMemoryProviderCreate(umfOsMemoryProviderOps(), &params, &hProvider);
    UT_ASSERTeq(ret, UMF_RESULT_SUCCESS);

    umf_memory_pool_handle_t pools[4];

    pools[0] = createDisjointPool(hProvider);
    pools[1] = createProxyPool(hProvider);
    pools[2] = createJemallocPool(hProvider);
    pools[3] = createScalablePool(hProvider);

    void *ptrs[4];

    for (int i = 0; i < 4; i++) {
        UT_ASSERTne(pools[i], NULL);
        ptrs[i] = umfPoolMalloc(pools[i], ALLOC_SIZE);
        UT_ASSERTne(ptrs[i], NULL);
    }

    for (int i = 0; i < 4; i++) {
        UT_ASSERTeq(umfPoolByPtr(ptrs[i]), pools[i]);
    }

    for (int i = 0; i < 4; i++) {
        umfFree(ptrs[i]);
    }

    for (int i = 0; i < 4; i++) {
        umfPoolDestroy(pools[i]);
    }

    umfMemoryProviderDestroy(hProvider);

    return 0;
}
