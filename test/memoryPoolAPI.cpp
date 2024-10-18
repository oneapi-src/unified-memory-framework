// Copyright (C) 2023-2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// This file contains tests for UMF pool API

#include "base.hpp"
#include "pool.hpp"
#include "poolFixtures.hpp"
#include "provider.hpp"
#include "provider_null.h"
#include "provider_trace.h"
#include "test_helpers.h"

#include <umf/memory_provider.h>
#include <umf/pools/pool_proxy.h>

#ifdef UMF_PROXY_LIB_ENABLED
#include <umf/proxy_lib_new_delete.h>
#endif

#include <array>
#include <string>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <variant>

using umf_test::test;
using namespace umf_test;

struct umfPoolWithCreateFlagsTest
    : umf_test::test,
      ::testing::WithParamInterface<umf_pool_create_flags_t> {
    void SetUp() override {
        test::SetUp();
        flags = this->GetParam();
        manuallyDestroyProvider = !(flags & UMF_POOL_CREATE_FLAG_OWN_PROVIDER);
    }
    umf_pool_create_flags_t flags;
    bool manuallyDestroyProvider = true;
};

TEST_P(umfPoolWithCreateFlagsTest, memoryPoolTrace) {
    using calls_type = std::unordered_map<std::string, size_t>;
    calls_type poolCalls;
    calls_type providerCalls;
    auto tracePool = [](void *handler, const char *name) {
        auto &poolCalls = *static_cast<calls_type *>(handler);
        ++poolCalls[name];
    };
    auto traceProvider = [](void *handler, const char *name) {
        auto &providerCalls = *static_cast<calls_type *>(handler);
        ++providerCalls[name];
    };

    auto nullProvider = nullProviderCreate();
    auto provider =
        traceProviderCreate(nullProvider, true, &providerCalls, traceProvider);

    auto proxyPool = wrapPoolUnique(
        createPoolChecked(umfProxyPoolOps(), provider, nullptr, flags));

    auto providerDesc = umf_test::wrapProviderUnique(nullProviderCreate());
    auto tracingPool = umf_test::wrapPoolUnique(tracePoolCreate(
        proxyPool.get(), providerDesc.get(), &poolCalls, tracePool));

    poolCalls.clear();
    providerCalls.clear();
    size_t pool_call_count = 0;
    size_t provider_call_count = 0;

    umfPoolMalloc(tracingPool.get(), 0);
    ASSERT_EQ(poolCalls["malloc"], 1);
    ASSERT_EQ(poolCalls.size(), ++pool_call_count);

    ASSERT_EQ(providerCalls["alloc"], 1);
    ASSERT_EQ(providerCalls.size(), ++provider_call_count);

    umfPoolMallocUsableSize(tracingPool.get(), nullptr);
    ASSERT_EQ(poolCalls["malloc_usable_size"], 1);
    ASSERT_EQ(poolCalls.size(), ++pool_call_count);

    ASSERT_EQ(providerCalls.size(), provider_call_count);

    umfPoolFree(tracingPool.get(), nullptr);
    ASSERT_EQ(poolCalls["free"], 1);
    ASSERT_EQ(poolCalls.size(), ++pool_call_count);

    ASSERT_EQ(providerCalls["free"], 1);
    ASSERT_EQ(providerCalls.size(), ++provider_call_count);

    umfPoolCalloc(tracingPool.get(), 0, 0);
    ASSERT_EQ(poolCalls["calloc"], 1);
    ASSERT_EQ(poolCalls.size(), ++pool_call_count);

    umfPoolRealloc(tracingPool.get(), nullptr, 0);
    ASSERT_EQ(poolCalls["realloc"], 1);
    ASSERT_EQ(poolCalls.size(), ++pool_call_count);

    umfPoolAlignedMalloc(tracingPool.get(), 0, 0);
    ASSERT_EQ(poolCalls["aligned_malloc"], 1);
    ASSERT_EQ(poolCalls.size(), ++pool_call_count);

    ASSERT_EQ(providerCalls["alloc"], 2);
    ASSERT_EQ(providerCalls.size(), provider_call_count);

    auto ret = umfPoolGetLastAllocationError(tracingPool.get());
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(poolCalls["get_last_native_error"], 1);
    ASSERT_EQ(poolCalls.size(), ++pool_call_count);

    if (manuallyDestroyProvider) {
        umfMemoryProviderDestroy(provider);
    }
}

TEST_P(umfPoolWithCreateFlagsTest, memoryPoolWithCustomProvider) {
    umf_memory_provider_handle_t hProvider = nullProviderCreate();

    struct pool : public umf_test::pool_base_t {
        umf_result_t
        initialize(umf_memory_provider_handle_t provider) noexcept {
            EXPECT_NE_NOEXCEPT(provider, nullptr);
            return UMF_RESULT_SUCCESS;
        }
    };
    umf_memory_pool_ops_t pool_ops = umf::poolMakeCOps<pool, void>();

    umf_memory_pool_handle_t hPool;
    auto ret = umfPoolCreate(&pool_ops, hProvider, nullptr, flags, &hPool);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(hPool, nullptr);

    umfPoolDestroy(hPool);

    if (manuallyDestroyProvider) {
        umfMemoryProviderDestroy(hProvider);
    }
}

TEST_F(test, retrieveMemoryProvider) {
    auto nullProvider = umf_test::wrapProviderUnique(nullProviderCreate());
    umf_memory_provider_handle_t provider = nullProvider.get();

    auto pool =
        wrapPoolUnique(createPoolChecked(umfProxyPoolOps(), provider, nullptr));

    umf_memory_provider_handle_t retProvider;
    auto ret = umfPoolGetMemoryProvider(pool.get(), &retProvider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(retProvider, provider);
}

TEST_F(test, BasicPoolByPtrTest) {
    constexpr size_t SIZE = 4096 * 1024;

    umf_memory_provider_handle_t provider;
    umf_result_t ret =
        umfMemoryProviderCreate(&MALLOC_PROVIDER_OPS, NULL, &provider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    auto pool =
        wrapPoolUnique(createPoolChecked(umfProxyPoolOps(), provider, nullptr,
                                         UMF_POOL_CREATE_FLAG_OWN_PROVIDER));
    auto expected_pool = pool.get();
    char *ptr = (char *)umfPoolMalloc(expected_pool, SIZE);
    ASSERT_NE(ptr, nullptr);

    auto ret_pool = umfPoolByPtr(ptr);
    EXPECT_EQ(ret_pool, expected_pool);

    ret_pool = umfPoolByPtr(ptr + SIZE);
    EXPECT_EQ(ret_pool, nullptr);

    ret_pool = umfPoolByPtr(ptr + SIZE - 1);
    EXPECT_EQ(ret_pool, expected_pool);

    ret = umfFree(ptr);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
}

INSTANTIATE_TEST_SUITE_P(
    mallocPoolTest, umfPoolTest,
    ::testing::Values(poolCreateExtParams{&MALLOC_POOL_OPS, nullptr,
                                          &UMF_NULL_PROVIDER_OPS, nullptr,
                                          nullptr},
                      poolCreateExtParams{umfProxyPoolOps(), nullptr,
                                          &MALLOC_PROVIDER_OPS, nullptr,
                                          nullptr}));

INSTANTIATE_TEST_SUITE_P(mallocMultiPoolTest, umfMultiPoolTest,
                         ::testing::Values(poolCreateExtParams{
                             umfProxyPoolOps(), nullptr, &MALLOC_PROVIDER_OPS,
                             nullptr, nullptr}));

INSTANTIATE_TEST_SUITE_P(umfPoolWithCreateFlagsTest, umfPoolWithCreateFlagsTest,
                         ::testing::Values(0,
                                           UMF_POOL_CREATE_FLAG_OWN_PROVIDER));

////////////////// Negative test cases /////////////////

TEST_P(umfPoolWithCreateFlagsTest, umfPoolCreateFlagsNullOps) {
    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t ret =
        umfMemoryProviderCreate(&UMF_NULL_PROVIDER_OPS, nullptr, &provider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    umf_memory_pool_handle_t pool = nullptr;
    ret = umfPoolCreate(nullptr, provider, nullptr, flags, &pool);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umfMemoryProviderDestroy(provider);
}

TEST_P(umfPoolWithCreateFlagsTest, umfPoolCreateFlagsNullPoolHandle) {
    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t ret =
        umfMemoryProviderCreate(&UMF_NULL_PROVIDER_OPS, nullptr, &provider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    ret = umfPoolCreate(umfProxyPoolOps(), provider, nullptr, flags, nullptr);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umfMemoryProviderDestroy(provider);
}

TEST_P(umfPoolWithCreateFlagsTest, umfPoolCreateFlagsInvalidProviders) {
    umf_memory_pool_handle_t hPool;
    auto ret = umfPoolCreate(&MALLOC_POOL_OPS, nullptr, nullptr, flags, &hPool);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

struct poolInitializeTest : umf_test::test,
                            ::testing::WithParamInterface<umf_result_t> {};

INSTANTIATE_TEST_SUITE_P(
    poolInitializeTest, poolInitializeTest,
    ::testing::Values(UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY,
                      UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC,
                      UMF_RESULT_ERROR_INVALID_ARGUMENT,
                      UMF_RESULT_ERROR_UNKNOWN));

TEST_P(poolInitializeTest, errorPropagation) {
    auto nullProvider = umf_test::wrapProviderUnique(nullProviderCreate());
    umf_memory_provider_handle_t hProvider = nullProvider.get();

    struct pool : public umf_test::pool_base_t {
        umf_result_t
        initialize([[maybe_unused]] umf_memory_provider_handle_t provider,
                   umf_result_t *errorToReturn) noexcept {
            return *errorToReturn;
        }
    };
    umf_memory_pool_ops_t pool_ops = umf::poolMakeCOps<pool, umf_result_t>();

    umf_memory_pool_handle_t hPool;
    auto ret = umfPoolCreate(&pool_ops, hProvider, (void *)&this->GetParam(), 0,
                             &hPool);
    ASSERT_EQ(ret, this->GetParam());
}

TEST_F(test, retrieveMemoryProvidersError) {
    auto nullProvider = umf_test::wrapProviderUnique(nullProviderCreate());
    umf_memory_provider_handle_t provider = nullProvider.get();

    auto pool =
        wrapPoolUnique(createPoolChecked(umfProxyPoolOps(), provider, nullptr));

    auto ret = umfPoolGetMemoryProvider(pool.get(), nullptr);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

// TODO: extend test for different functions (not only alloc)
TEST_F(test, getLastFailedMemoryProvider) {
    static constexpr size_t allocSize = 8;
    static umf_result_t allocResult = UMF_RESULT_SUCCESS;

    struct memory_provider : public umf_test::provider_base_t {
        umf_result_t initialize(const char *inName) {
            name = inName;
            return UMF_RESULT_SUCCESS;
        }

        umf_result_t alloc(size_t size, size_t, void **ptr) noexcept {
            if (allocResult == UMF_RESULT_SUCCESS) {
                *ptr = malloc(size);
            } else {
                *ptr = nullptr;
            }

            return allocResult;
        }

        umf_result_t free(void *ptr, [[maybe_unused]] size_t size) noexcept {
            ::free(ptr);
            return UMF_RESULT_SUCCESS;
        }

        const char *get_name() noexcept { return this->name; }

        const char *name;
    };
    umf_memory_provider_ops_t provider_ops =
        umf::providerMakeCOps<memory_provider, char>();

    auto providerUnique1 = wrapProviderUnique(
        createProviderChecked(&provider_ops, (void *)"provider1"));
    auto providerUnique2 = wrapProviderUnique(
        createProviderChecked(&provider_ops, (void *)"provider2"));

    auto hProvider = providerUnique1.get();
    auto pool = wrapPoolUnique(
        createPoolChecked(umfProxyPoolOps(), hProvider, nullptr));

    auto ptr = umfPoolMalloc(pool.get(), allocSize);
    ASSERT_NE(ptr, nullptr);
    umfPoolFree(pool.get(), ptr);

    // make provider return an error during allocation
    allocResult = UMF_RESULT_ERROR_UNKNOWN;
    ptr = umfPoolMalloc(pool.get(), allocSize);
    ASSERT_EQ(ptr, nullptr);
    ASSERT_EQ(std::string_view(
                  umfMemoryProviderGetName(umfGetLastFailedMemoryProvider())),
              "provider1");

    auto ret =
        umfMemoryProviderAlloc(providerUnique2.get(), allocSize, 0, &ptr);
    ASSERT_NE(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(ptr, nullptr);
    ASSERT_EQ(std::string_view(
                  umfMemoryProviderGetName(umfGetLastFailedMemoryProvider())),
              "provider2");

    // successful provider should not be returned by umfGetLastFailedMemoryProvider
    allocResult = UMF_RESULT_SUCCESS;
    ptr = umfPoolMalloc(pool.get(), allocSize);
    ASSERT_NE(ptr, nullptr);
    ASSERT_EQ(std::string_view(
                  umfMemoryProviderGetName(umfGetLastFailedMemoryProvider())),
              "provider2");
    umfPoolFree(pool.get(), ptr);

    // error in another thread should not impact umfGetLastFailedMemoryProvider on this thread
    allocResult = UMF_RESULT_ERROR_UNKNOWN;
    std::thread t([&, hPool = pool.get()] {
        ptr = umfPoolMalloc(hPool, allocSize);
        ASSERT_EQ(ptr, nullptr);
        ASSERT_EQ(std::string_view(umfMemoryProviderGetName(
                      umfGetLastFailedMemoryProvider())),
                  "provider1");
    });
    t.join();

    ASSERT_EQ(std::string_view(
                  umfMemoryProviderGetName(umfGetLastFailedMemoryProvider())),
              "provider2");
}

// This fixture can be instantiated with any function that accepts void
// and returns any of the results listed inside the variant type.
struct poolHandleCheck
    : umf_test::test,
      ::testing::WithParamInterface<
          std::function<std::variant<void *, umf_result_t, size_t>(void)>> {};

TEST_P(poolHandleCheck, poolHandleCheckAll) {
    const auto &f = GetParam();
    auto ret = f();

    std::visit(
        [&](auto arg) {
            using T = decltype(arg);
            if constexpr (std::is_same_v<T, umf_result_t>) {
                ASSERT_EQ(arg, UMF_RESULT_ERROR_INVALID_ARGUMENT);
            } else if constexpr (std::is_same_v<T, size_t>) {
                ASSERT_EQ(arg, 0U);
            } else {
                ASSERT_EQ(arg, nullptr);
            }
        },
        ret);
}

// Run poolHandleCheck for each function listed below. Each function
// will be called with zero-initialized arguments.
INSTANTIATE_TEST_SUITE_P(
    poolHandleCheck, poolHandleCheck,
    ::testing::Values(
        umf_test::withGeneratedArgs(umfPoolMalloc),
        umf_test::withGeneratedArgs(umfPoolAlignedMalloc),
        umf_test::withGeneratedArgs(umfPoolFree),
        umf_test::withGeneratedArgs(umfPoolCalloc),
        umf_test::withGeneratedArgs(umfPoolRealloc),
        umf_test::withGeneratedArgs(umfPoolMallocUsableSize),
        umf_test::withGeneratedArgs(umfPoolGetLastAllocationError)));
