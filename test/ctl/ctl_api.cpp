/*
 *
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <umf.h>
#include <umf/memory_pool.h>
#include <umf/memory_provider.h>
#include <umf/pools/pool_scalable.h>
#include <umf/providers/provider_os_memory.h>

#include "../common/base.hpp"
#include "gtest/gtest.h"

using namespace umf_test;

TEST_F(test, ctl_by_handle_os_provider) {
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

    int ipc_enabled = 0xBAD;
    ret = umfCtlGet("umf.provider.by_handle.params.ipc_enabled", hProvider,
                    &ipc_enabled);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(ipc_enabled, 0);

    umfOsMemoryProviderParamsDestroy(os_memory_provider_params);
    umfMemoryProviderDestroy(hProvider);
}

// Create a memory provider and a memory pool
umf_memory_provider_handle_t create_memory_provider() {
    umf_memory_provider_ops_t *provider_ops = umfOsMemoryProviderOps();
    umf_os_memory_provider_params_handle_t params = NULL;
    umf_memory_provider_handle_t provider;

    int ret = umfOsMemoryProviderParamsCreate(&params);
    if (ret != UMF_RESULT_SUCCESS) {
        return 0;
    }

    ret = umfMemoryProviderCreate(provider_ops, params, &provider);
    umfOsMemoryProviderParamsDestroy(params);
    if (ret != UMF_RESULT_SUCCESS) {
        return 0;
    }

    return provider;
}

TEST_F(test, ctl_by_handle_pool) {
    umf_pool_create_flags_t flags[] = {
        0,
        UMF_POOL_CREATE_FLAG_DISABLE_TRACKING,
    };
    size_t num_flags = sizeof(flags) / sizeof(flags[0]);

    for (size_t i = 0; i < num_flags; i++) {
        umf_memory_provider_handle_t provider = create_memory_provider();
        if (provider == NULL) {
            GTEST_SKIP() << "Failed to create a memory provider!";
        }

        umf_memory_pool_ops_t *pool_ops = umfScalablePoolOps();
        void *pool_params = NULL;
        umf_memory_pool_handle_t pool;

        int ret =
            umfPoolCreate(pool_ops, provider, pool_params, flags[i], &pool);
        if (ret != UMF_RESULT_SUCCESS) {
            GTEST_SKIP();
        }

        int tracking_status = 0xBAD;
        ret = umfCtlGet("umf.pool.by_handle.params.tracking_enabled", pool,
                        &tracking_status);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        ASSERT_EQ(tracking_status, (flags[i] == 0) ? 1 : 0);

        umfPoolDestroy(pool);
        umfMemoryProviderDestroy(provider);
    }
}
