// Copyright (C) 2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exceptiongi

#include <cstdint>
#include <gtest/gtest.h>
#include <umf/memory_pool.h>
#include <umf/memory_provider.h>
#include <umf/memory_provider_ops.h>
#include <umf/pools/pool_disjoint.h>
#include <umf/providers/provider_os_memory.h>

#include "base.hpp"
#include "utils_log.h"

using umf_test::test;
using namespace umf_test;

#define ASSERT_SUCCESS(ret) ASSERT_EQ(ret, UMF_RESULT_SUCCESS)

// Encapsulating class for pool creation and destruction
class PoolWrapper {
  public:
    PoolWrapper(umf_memory_provider_handle_t provider,
                const umf_memory_pool_ops_t *poolOps,
                umf_disjoint_pool_params_handle_t params = nullptr)
        : m_pool(nullptr), m_provider(provider), m_poolOps(poolOps),
          m_params(params) {
        auto res = umfPoolCreate(m_poolOps, m_provider, m_params, 0, &m_pool);
        if (res != UMF_RESULT_SUCCESS) {
            m_pool = nullptr;
        }
    }

    ~PoolWrapper() {
        if (m_pool) {
            umfPoolDestroy(m_pool);
        }
    }

    umf_memory_pool_handle_t get() const { return m_pool; }

    // Disallow copy and move
    PoolWrapper(const PoolWrapper &) = delete;
    PoolWrapper &operator=(const PoolWrapper &) = delete;
    PoolWrapper(PoolWrapper &&) = delete;
    PoolWrapper &operator=(PoolWrapper &&) = delete;

  private:
    umf_memory_pool_handle_t m_pool;
    umf_memory_provider_handle_t m_provider;
    const umf_memory_pool_ops_t *m_poolOps;
    umf_disjoint_pool_params_handle_t m_params;
};

// Encapsulating class for provider creation and destruction
class ProviderWrapper {
  public:
    ProviderWrapper(const umf_memory_provider_ops_t *providerOps,
                    void *params = nullptr)
        : m_provider(nullptr), m_providerOps(providerOps), m_params(params) {
        auto res =
            umfMemoryProviderCreate(m_providerOps, m_params, &m_provider);
        if (res != UMF_RESULT_SUCCESS) {
            m_provider = nullptr;
        }
    }

    ~ProviderWrapper() {
        if (m_provider) {
            umfMemoryProviderDestroy(m_provider);
        }
    }

    umf_memory_provider_handle_t get() const { return m_provider; }

    // Disallow copy and move
    ProviderWrapper(const ProviderWrapper &) = delete;
    ProviderWrapper &operator=(const ProviderWrapper &) = delete;
    ProviderWrapper(ProviderWrapper &&) = delete;
    ProviderWrapper &operator=(ProviderWrapper &&) = delete;

  private:
    umf_memory_provider_handle_t m_provider;
    const umf_memory_provider_ops_t *m_providerOps;
    void *m_params;
};

TEST_F(test, disjointCtlAllocationBalance) {
    umf_os_memory_provider_params_handle_t os_memory_provider_params = nullptr;
    if (UMF_RESULT_ERROR_NOT_SUPPORTED ==
        umfOsMemoryProviderParamsCreate(&os_memory_provider_params)) {
        GTEST_SKIP() << "OS memory provider is not supported!";
    }

    ProviderWrapper providerWrapper(umfOsMemoryProviderOps(),
                                    os_memory_provider_params);
    if (providerWrapper.get() == NULL) {
        GTEST_SKIP() << "OS memory provider is not supported!";
    }

    umf_disjoint_pool_params_handle_t params = nullptr;
    ASSERT_SUCCESS(umfDisjointPoolParamsCreate(&params));

    // Set max poolable size to a reasonable value
    ASSERT_SUCCESS(
        umfDisjointPoolParamsSetMaxPoolableSize(params, 1024 * 1024));

    // Set the capacity of the pool to a reasonable value
    ASSERT_SUCCESS(
        umfDisjointPoolParamsSetSlabMinSize(params, 64 * 1024)); // 64 KiB

    // Set the trace level to 3 to enable allocation balance tracking
    ASSERT_SUCCESS(umfDisjointPoolParamsSetTrace(params, 3));

    PoolWrapper poolWrapper(providerWrapper.get(), umfDisjointPoolOps(),
                            params);

    // Check that the allocation balance is zero
    uint64_t allocation_balance = 0;
    ASSERT_SUCCESS(umfCtlGet("umf.pool.by_handle.disjoint.allocation_balance",
                             poolWrapper.get(), &allocation_balance,
                             sizeof(allocation_balance)));
    ASSERT_EQ(allocation_balance, 0ull);

    // Allocate some memory from the pool
    size_t allocation_size = 64; // 64 B
    const uint64_t max_allocations = 2;
    void *ptr[max_allocations] = {nullptr};
    uint64_t i = 0;
    while (i < max_allocations) {
        ptr[i] = umfPoolMalloc(poolWrapper.get(), allocation_size);
        ASSERT_NE(ptr[i], nullptr);
        ++i;
    }

    // Check the allocation balance after allocations
    ASSERT_SUCCESS(umfCtlGet("umf.pool.by_handle.disjoint.allocation_balance",
                             poolWrapper.get(), &allocation_balance,
                             sizeof(allocation_balance)));
    ASSERT_EQ(allocation_balance, max_allocations);

    // Check balance after freeing the allocations
    for (uint64_t j = 0; j < max_allocations; ++j) {
        if (ptr[j]) {
            ASSERT_EQ(umfPoolFree(poolWrapper.get(), ptr[j]),
                      UMF_RESULT_SUCCESS);
        }
    }
    allocation_balance = 123;
    ASSERT_SUCCESS(umfCtlGet("umf.pool.by_handle.disjoint.allocation_balance",
                             poolWrapper.get(), &allocation_balance,
                             sizeof(allocation_balance)));
    ASSERT_EQ(allocation_balance, 0ull);

    ASSERT_SUCCESS(umfDisjointPoolParamsDestroy(params));
    ASSERT_SUCCESS(umfOsMemoryProviderParamsDestroy(os_memory_provider_params));
}

TEST_F(test, disjointCtlName) {
    umf_os_memory_provider_params_handle_t os_memory_provider_params = nullptr;
    if (UMF_RESULT_ERROR_NOT_SUPPORTED ==
        umfOsMemoryProviderParamsCreate(&os_memory_provider_params)) {
        GTEST_SKIP() << "OS memory provider is not supported!";
    }

    ProviderWrapper providerWrapper(umfOsMemoryProviderOps(),
                                    os_memory_provider_params);
    if (providerWrapper.get() == NULL) {
        GTEST_SKIP() << "OS memory provider is not supported!";
    }

    // Set default name
    const char *val = "disjoint_new_name";
    ASSERT_SUCCESS(umfCtlSet("umf.pool.default.disjoint.name", NULL,
                             (void *)val, strlen(val)));

    umf_disjoint_pool_params_handle_t params = nullptr;
    ASSERT_SUCCESS(umfDisjointPoolParamsCreate(&params));
    PoolWrapper poolWrapper(providerWrapper.get(), umfDisjointPoolOps(),
                            params);

    // Check that the default name is correctly set
    const char *name = umfPoolGetName(poolWrapper.get());
    ASSERT_STREQ(name, val);

    // Clean up
    ASSERT_SUCCESS(umfDisjointPoolParamsDestroy(params));
    ASSERT_SUCCESS(umfOsMemoryProviderParamsDestroy(os_memory_provider_params));
}

TEST_F(test, disjointCtlChangeNameTwice) {
    umf_os_memory_provider_params_handle_t os_memory_provider_params = nullptr;
    if (UMF_RESULT_ERROR_NOT_SUPPORTED ==
        umfOsMemoryProviderParamsCreate(&os_memory_provider_params)) {
        GTEST_SKIP() << "OS memory provider is not supported!";
    }
    ProviderWrapper providerWrapper(umfOsMemoryProviderOps(),
                                    os_memory_provider_params);
    if (providerWrapper.get() == NULL) {
        GTEST_SKIP() << "OS memory provider is not supported!";
    }
    // Set default name
    const char *val = "disjoint_new_name";
    const char *val2 = "another_name";
    ASSERT_SUCCESS(umfCtlSet("umf.pool.default.disjoint.name", NULL,
                             (void *)val, strlen(val)));
    ASSERT_SUCCESS(umfCtlSet("umf.pool.default.disjoint.name", NULL,
                             (void *)val2, strlen(val2)));

    umf_disjoint_pool_params_handle_t params = nullptr;
    ASSERT_SUCCESS(umfDisjointPoolParamsCreate(&params));
    PoolWrapper poolWrapper(providerWrapper.get(), umfDisjointPoolOps(),
                            params);

    // Check that the default name is correctly set
    const char *name = umfPoolGetName(poolWrapper.get());
    ASSERT_STREQ(name, val2);

    // Clean up
    ASSERT_SUCCESS(umfDisjointPoolParamsDestroy(params));
    ASSERT_SUCCESS(umfOsMemoryProviderParamsDestroy(os_memory_provider_params));
}
