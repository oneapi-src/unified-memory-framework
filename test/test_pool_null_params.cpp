/*
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <gtest/gtest.h>

#include <umf/memory_pool.h>
#include <umf/memory_provider.h>
#include <umf/pools/pool_disjoint.h>
#include <umf/pools/pool_jemalloc.h>
#include <umf/pools/pool_proxy.h>
#include <umf/pools/pool_scalable.h>

#include "provider_null.h"

// Dummy provider implementation for testing
static umf_memory_provider_ops_t dummy_provider_ops = UMF_NULL_PROVIDER_OPS;

using PoolOpsFn = const umf_memory_pool_ops_t *(*)();

class PoolNullParamsTest : public ::testing::TestWithParam<PoolOpsFn> {
  protected:
    umf_memory_provider_handle_t provider = NULL;
    void SetUp() override {
        ASSERT_EQ(umfMemoryProviderCreate(&dummy_provider_ops, NULL, &provider),
                  UMF_RESULT_SUCCESS);
    }
    void TearDown() override {
        if (provider) {
            umfMemoryProviderDestroy(provider);
        }
    }
};

TEST_P(PoolNullParamsTest, CreateWithNullParams) {
    umf_memory_pool_handle_t pool;
    PoolOpsFn opsFn = GetParam();
    umf_result_t res = umfPoolCreate(opsFn(), provider, NULL, 0, &pool);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    umfPoolDestroy(pool);
}

namespace {
const PoolOpsFn poolOpsList[] = {
#if defined(UMF_POOL_SCALABLE_ENABLED)
    &umfScalablePoolOps,
#endif
#if defined(UMF_POOL_JEMALLOC_ENABLED)
    &umfJemallocPoolOps,
#endif
#if defined(UMF_POOL_PROXY_ENABLED)
    &umfProxyPoolOps
#endif
        &umfDisjointPoolOps};
} // namespace

INSTANTIATE_TEST_SUITE_P(poolNullParamsTest, PoolNullParamsTest,
                         ::testing::ValuesIn(poolOpsList));
