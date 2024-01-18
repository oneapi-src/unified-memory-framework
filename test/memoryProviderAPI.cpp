// Copyright (C) 2023-2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// This file contains tests for UMF provider API

#include "provider.hpp"
#include "provider_null.h"
#include "test_helpers.h"

#include <string>
#include <unordered_map>
#include <variant>

using umf_test::test;

TEST_F(test, memoryProviderTrace) {
    static std::unordered_map<std::string, size_t> calls;
    auto trace = [](const char *name) { calls[name]++; };

    auto nullProvider = umf_test::wrapProviderUnique(nullProviderCreate());
    auto tracingProvider = umf_test::wrapProviderUnique(
        traceProviderCreate(nullProvider.get(), trace));

    size_t call_count = 0;

    void *ptr;
    auto ret = umfMemoryProviderAlloc(tracingProvider.get(), 0, 0, &ptr);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(calls["alloc"], 1);
    ASSERT_EQ(calls.size(), ++call_count);

    ret = umfMemoryProviderFree(tracingProvider.get(), nullptr, 0);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(calls["free"], 1);
    ASSERT_EQ(calls.size(), ++call_count);

    umfMemoryProviderGetLastNativeError(tracingProvider.get(), nullptr,
                                        nullptr);
    ASSERT_EQ(calls["get_last_native_error"], 1);
    ASSERT_EQ(calls.size(), ++call_count);

    ret = umfMemoryProviderGetRecommendedPageSize(tracingProvider.get(), 0,
                                                  nullptr);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(calls["get_recommended_page_size"], 1);
    ASSERT_EQ(calls.size(), ++call_count);

    ret = umfMemoryProviderGetMinPageSize(tracingProvider.get(), nullptr,
                                          nullptr);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(calls["get_min_page_size"], 1);
    ASSERT_EQ(calls.size(), ++call_count);

    ret = umfMemoryProviderPurgeLazy(tracingProvider.get(), nullptr, 0);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(calls["purge_lazy"], 1);
    ASSERT_EQ(calls.size(), ++call_count);

    ret = umfMemoryProviderPurgeForce(tracingProvider.get(), nullptr, 0);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(calls["purge_force"], 1);
    ASSERT_EQ(calls.size(), ++call_count);

    const char *pName = umfMemoryProviderGetName(tracingProvider.get());
    ASSERT_EQ(calls["name"], 1);
    ASSERT_EQ(calls.size(), ++call_count);
    ASSERT_EQ(std::string(pName), std::string("null"));
}

////////////////// Negative test cases /////////////////

TEST_F(test, memoryProviderCreateNullOps) {
    umf_memory_provider_handle_t hProvider;
    auto ret = umfMemoryProviderCreate(nullptr, nullptr, &hProvider);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_F(test, memoryProviderNullPoolHandle) {
    auto ret =
        umfMemoryProviderCreate(&UMF_NULL_PROVIDER_OPS, nullptr, nullptr);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

struct providerInitializeTest : umf_test::test,
                                ::testing::WithParamInterface<umf_result_t> {};

INSTANTIATE_TEST_SUITE_P(
    providerInitializeTest, providerInitializeTest,
    ::testing::Values(UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY,
                      UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC,
                      UMF_RESULT_ERROR_INVALID_ARGUMENT,
                      UMF_RESULT_ERROR_UNKNOWN));

TEST_P(providerInitializeTest, errorPropagation) {
    struct provider : public umf_test::provider_base_t {
        umf_result_t initialize(umf_result_t *errorToReturn) noexcept {
            return *errorToReturn;
        }
    };
    umf_memory_provider_ops_t provider_ops =
        umf::providerMakeCOps<provider, umf_result_t>();

    umf_memory_provider_handle_t hProvider;
    auto ret = umfMemoryProviderCreate(&provider_ops, (void *)&this->GetParam(),
                                       &hProvider);
    ASSERT_EQ(ret, this->GetParam());
}

// This fixture can be instantiated with any function that accepts void
// and returns any of the results listed inside the variant type.
struct providerHandleCheck
    : umf_test::test,
      ::testing::WithParamInterface<
          std::function<std::variant<const char *, umf_result_t>(void)>> {};

TEST_P(providerHandleCheck, providerHandleCheckAll) {
    auto f = GetParam();
    auto ret = f();

    std::visit(
        [&](auto arg) {
            using T = decltype(arg);
            if constexpr (std::is_same_v<T, umf_result_t>) {
                ASSERT_EQ(arg, UMF_RESULT_ERROR_INVALID_ARGUMENT);
            } else {
                ASSERT_EQ(arg, nullptr);
            }
        },
        ret);
}

// Run poolHandleCheck for each function listed below. Each function
// will be called with zero-initialized arguments.
INSTANTIATE_TEST_SUITE_P(
    providerHandleCheck, providerHandleCheck,
    ::testing::Values(
        umf_test::withGeneratedArgs(umfMemoryProviderAlloc),
        umf_test::withGeneratedArgs(umfMemoryProviderFree),
        umf_test::withGeneratedArgs(umfMemoryProviderGetRecommendedPageSize),
        umf_test::withGeneratedArgs(umfMemoryProviderGetMinPageSize),
        umf_test::withGeneratedArgs(umfMemoryProviderPurgeLazy),
        umf_test::withGeneratedArgs(umfMemoryProviderPurgeForce),
        umf_test::withGeneratedArgs(umfMemoryProviderGetName)));
