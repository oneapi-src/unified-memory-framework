// Copyright (C) 2023 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "../src/memory_pool_internal.h"
#include "base.hpp"
#include "common/provider_null.h"
#include "pool.hpp"
#include "provider_trace.h"
#include "test_helpers.h"

#include <unordered_map>

using umf_test::test;

template <typename T> umf_memory_pool_ops_t poolNoParamsMakeCOps() {
    umf_memory_pool_ops_t ops = umf::detail::poolOpsBase<T>();

    ops.initialize = [](umf_memory_provider_handle_t provider, void *params,
                        void **obj) {
        (void)params;
        try {
            *obj = new T;
        } catch (...) {
            return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        }

        return umf::detail::initialize<T>(reinterpret_cast<T *>(*obj),
                                          std::make_tuple(provider));
    };

    return ops;
}

umf_memory_pool_ops_t PROXY_POOL_OPS =
    poolNoParamsMakeCOps<umf_test::proxy_pool>();

TEST_F(test, poolCreateExSuccess) {
    umf_memory_pool_handle_t pool = nullptr;
    auto ret = umfPoolCreateEx(&PROXY_POOL_OPS, nullptr, &UMF_NULL_PROVIDER_OPS,
                               nullptr, &pool);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(pool, nullptr);

    umfPoolDestroy(pool);
}

TEST_F(test, poolCreateExNullPoolOps) {
    umf_memory_pool_handle_t pool = nullptr;
    auto ret = umfPoolCreateEx(nullptr, nullptr, &UMF_NULL_PROVIDER_OPS,
                               nullptr, &pool);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_F(test, poolCreateExNullProviderOps) {
    umf_memory_pool_handle_t pool = nullptr;
    auto ret =
        umfPoolCreateEx(&PROXY_POOL_OPS, nullptr, nullptr, nullptr, &pool);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_F(test, poolCreateExNullPoolHandle) {
    auto ret = umfPoolCreateEx(&PROXY_POOL_OPS, nullptr, &UMF_NULL_PROVIDER_OPS,
                               nullptr, nullptr);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_F(test, poolCreateExCountProviderCalls) {
    auto nullProvider = umf_test::wrapProviderUnique(nullProviderCreate());

    static std::unordered_map<std::string, size_t> providerCalls;
    auto traceCb = [](const char *name) { providerCalls[name]++; };

    umf_provider_trace_params_t provider_params = {nullProvider.get(), traceCb};

    umf_memory_pool_handle_t pool = nullptr;
    umf_result_t ret =
        umfPoolCreateEx(&PROXY_POOL_OPS, nullptr, &UMF_TRACE_PROVIDER_OPS,
                        &provider_params, &pool);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(pool, nullptr);

    size_t provider_call_count = 0;

    umfPoolMalloc(pool, 0);
    ASSERT_EQ(providerCalls["alloc"], 1);
    ASSERT_EQ(providerCalls.size(), ++provider_call_count);

    umfPoolFree(pool, 0);
    ASSERT_EQ(providerCalls["free"], 1);
    ASSERT_EQ(providerCalls.size(), ++provider_call_count);

    umfPoolCalloc(pool, 0, 0);
    ASSERT_EQ(providerCalls["alloc"], 2);
    ASSERT_EQ(providerCalls.size(), provider_call_count);

    umfPoolAlignedMalloc(pool, 0, 0);
    ASSERT_EQ(providerCalls["alloc"], 3);
    ASSERT_EQ(providerCalls.size(), provider_call_count);

    umfPoolDestroy(pool);
}
