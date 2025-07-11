// Copyright (C) 2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exceptiongi

#include <gtest/gtest.h>
#include <umf/experimental/ctl.h>
#include <umf/memory_pool.h>
#include <umf/memory_provider.h>
#include <umf/memory_provider_ops.h>
#include <umf/pools/pool_disjoint.h>
#include <umf/providers/provider_os_memory.h>

#include <vector>

#include "base.hpp"
#include "utils_assert.h"
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
    const char *name = NULL;
    ASSERT_SUCCESS(umfPoolGetName(poolWrapper.get(), &name));
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
    const char *name = NULL;
    ASSERT_SUCCESS(umfPoolGetName(poolWrapper.get(), &name));
    ASSERT_STREQ(name, val2);

    // Clean up
    ASSERT_SUCCESS(umfDisjointPoolParamsDestroy(params));
    ASSERT_SUCCESS(umfOsMemoryProviderParamsDestroy(os_memory_provider_params));
}

TEST_F(test, disjointCtlUsedMemory) {
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

    const size_t slab_min_size = 64 * 1024;
    umfDisjointPoolParamsSetMinBucketSize(params, slab_min_size);

    PoolWrapper poolWrapper(providerWrapper.get(), umfDisjointPoolOps(),
                            params);

    // Initially, used memory should be 0
    size_t used_memory = 0;
    ASSERT_SUCCESS(umfCtlGet("umf.pool.by_handle.disjoint.used_memory",
                             poolWrapper.get(), &used_memory,
                             sizeof(used_memory)));
    ASSERT_EQ(used_memory, 0ull);

    // Allocate some memory
    void *ptr1 = umfPoolMalloc(poolWrapper.get(), 1024ull);
    ASSERT_NE(ptr1, nullptr);

    // Check that used memory increased
    ASSERT_SUCCESS(umfCtlGet("umf.pool.by_handle.disjoint.used_memory",
                             poolWrapper.get(), &used_memory,
                             sizeof(used_memory)));
    ASSERT_GE(used_memory, 1024ull);

    // Allocate more memory
    void *ptr2 = umfPoolMalloc(poolWrapper.get(), 2048ull);
    ASSERT_NE(ptr2, nullptr);

    size_t used_memory2 = 0;
    ASSERT_SUCCESS(umfCtlGet("umf.pool.by_handle.disjoint.used_memory",
                             poolWrapper.get(), &used_memory2,
                             sizeof(used_memory2)));
    ASSERT_GE(used_memory2, used_memory + 2048ull);

    // Free memory
    ASSERT_SUCCESS(umfPoolFree(poolWrapper.get(), ptr1));
    ASSERT_SUCCESS(umfPoolFree(poolWrapper.get(), ptr2));

    // Check that used memory is equal to 0
    size_t used_memory3 = 0;
    ASSERT_SUCCESS(umfCtlGet("umf.pool.by_handle.disjoint.used_memory",
                             poolWrapper.get(), &used_memory3,
                             sizeof(used_memory3)));
    ASSERT_EQ(used_memory3, 0ull);

    // Allocate again at least slab_min_size
    void *ptr3 = umfPoolMalloc(poolWrapper.get(), slab_min_size);
    ASSERT_NE(ptr3, nullptr);

    // Check that used memory increased
    size_t used_memory4 = 0;
    ASSERT_SUCCESS(umfCtlGet("umf.pool.by_handle.disjoint.used_memory",
                             poolWrapper.get(), &used_memory4,
                             sizeof(used_memory4)));
    ASSERT_EQ(used_memory4, slab_min_size);

    // Clean up
    ASSERT_SUCCESS(umfDisjointPoolParamsDestroy(params));
    ASSERT_SUCCESS(umfOsMemoryProviderParamsDestroy(os_memory_provider_params));
}

TEST_F(test, disjointCtlReservedMemory) {
    umf_os_memory_provider_params_handle_t os_memory_provider_params = nullptr;
    const size_t slab_min_size = 64 * 1024;

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

    // Set minimum slab size
    umfDisjointPoolParamsSetSlabMinSize(params, slab_min_size);

    PoolWrapper poolWrapper(providerWrapper.get(), umfDisjointPoolOps(),
                            params);

    // Initially, reserved memory should be 0
    size_t reserved_memory = 0;
    ASSERT_SUCCESS(umfCtlGet("umf.pool.by_handle.disjoint.reserved_memory",
                             poolWrapper.get(), &reserved_memory,
                             sizeof(reserved_memory)));
    ASSERT_EQ(reserved_memory, 0ull);

    // Allocate some memory
    void *ptr1 = umfPoolMalloc(poolWrapper.get(), 1024ull);
    ASSERT_NE(ptr1, nullptr);

    // Check that reserved memory increased (should be at least slab_min_size)
    ASSERT_SUCCESS(umfCtlGet("umf.pool.by_handle.disjoint.reserved_memory",
                             poolWrapper.get(), &reserved_memory,
                             sizeof(reserved_memory)));
    ASSERT_GE(reserved_memory, slab_min_size);

    void *ptr2 = umfPoolMalloc(poolWrapper.get(), 1024ull);
    ASSERT_NE(ptr2, nullptr);

    size_t reserved_memory2 = 0;
    ASSERT_SUCCESS(umfCtlGet("umf.pool.by_handle.disjoint.reserved_memory",
                             poolWrapper.get(), &reserved_memory2,
                             sizeof(reserved_memory2)));
    size_t used_memory = 0;
    ASSERT_SUCCESS(umfCtlGet("umf.pool.by_handle.disjoint.used_memory",
                             poolWrapper.get(), &used_memory,
                             sizeof(used_memory)));

    ASSERT_GE(reserved_memory2, slab_min_size);

    // Free memory - reserved memory should stay the same
    ASSERT_SUCCESS(umfPoolFree(poolWrapper.get(), ptr1));
    ASSERT_SUCCESS(umfPoolFree(poolWrapper.get(), ptr2));

    size_t reserved_memory3 = 0;
    ASSERT_SUCCESS(umfCtlGet("umf.pool.by_handle.disjoint.reserved_memory",
                             poolWrapper.get(), &reserved_memory3,
                             sizeof(reserved_memory3)));
    ASSERT_EQ(reserved_memory3, slab_min_size);

    // Clean up
    ASSERT_SUCCESS(umfDisjointPoolParamsDestroy(params));
    ASSERT_SUCCESS(umfOsMemoryProviderParamsDestroy(os_memory_provider_params));
}

TEST_F(test, disjointCtlMemoryMetricsConsistency) {
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

    // Set minimum slab size
    size_t slab_min_size = 64 * 1024;
    ASSERT_SUCCESS(umfDisjointPoolParamsSetSlabMinSize(params, slab_min_size));
    ASSERT_SUCCESS(umfDisjointPoolParamsSetCapacity(params, 4));

    PoolWrapper poolWrapper(providerWrapper.get(), umfDisjointPoolOps(),
                            params);

    const size_t n_allocations = 10; // Number of allocations
 
    // Allocate memory
    std::vector<void *> ptrs;
    for (size_t i = 0; i < n_allocations; i++) {
        void *ptr = umfPoolMalloc(poolWrapper.get(), slab_min_size);
        ASSERT_NE(ptr, nullptr);
        ptrs.push_back(ptr);
    }

    // Get memory metrics
    size_t used_memory = 0;
    size_t reserved_memory = 0;
    ASSERT_SUCCESS(umfCtlGet("umf.pool.by_handle.disjoint.used_memory",
                             poolWrapper.get(), &used_memory,
                             sizeof(used_memory)));
    ASSERT_SUCCESS(umfCtlGet("umf.pool.by_handle.disjoint.reserved_memory",
                             poolWrapper.get(), &reserved_memory,
                             sizeof(reserved_memory)));

    // Used memory should be at least the total allocated
    ASSERT_GE(used_memory, n_allocations * slab_min_size);

    // Reserved memory should be at least the used memory
    ASSERT_GE(reserved_memory, 4 * slab_min_size);

    // Free all memory
    for (void *ptr : ptrs) {
        ASSERT_SUCCESS(umfPoolFree(poolWrapper.get(), ptr));
    }

    // Check metrics after free
    size_t used_memory_after = 0;
    size_t reserved_memory_after = 0;
    ASSERT_SUCCESS(umfCtlGet("umf.pool.by_handle.disjoint.used_memory",
                             poolWrapper.get(), &used_memory_after,
                             sizeof(used_memory_after)));
    ASSERT_SUCCESS(umfCtlGet("umf.pool.by_handle.disjoint.reserved_memory",
                             poolWrapper.get(), &reserved_memory_after,
                             sizeof(reserved_memory_after)));

    // Used memory should be 0 after freeing
    ASSERT_EQ(used_memory_after, 0ull);
    // Reserved memory should remain the same (pooling)
    ASSERT_EQ(reserved_memory_after, 4 * slab_min_size);

    // Clean up
    ASSERT_SUCCESS(umfDisjointPoolParamsDestroy(params));
    ASSERT_SUCCESS(umfOsMemoryProviderParamsDestroy(os_memory_provider_params));
}

TEST_F(test, disjointCtlMemoryMetricsInvalidArgs) {
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
    PoolWrapper poolWrapper(providerWrapper.get(), umfDisjointPoolOps(),
                            params);

    // Test invalid arguments
    size_t value = 0;

    // NULL arg pointer
    ASSERT_EQ(umfCtlGet("umf.pool.by_handle.disjoint.used_memory",
                        poolWrapper.get(), NULL, sizeof(value)),
              UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // Size too small
    ASSERT_EQ(umfCtlGet("umf.pool.by_handle.disjoint.used_memory",
                        poolWrapper.get(), &value, sizeof(size_t) / 2),
              UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // Same tests for reserved_memory
    ASSERT_EQ(umfCtlGet("umf.pool.by_handle.disjoint.reserved_memory",
                        poolWrapper.get(), NULL, sizeof(value)),
              UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ASSERT_EQ(umfCtlGet("umf.pool.by_handle.disjoint.reserved_memory",
                        poolWrapper.get(), &value, sizeof(size_t) / 2),
              UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // Clean up
    ASSERT_SUCCESS(umfDisjointPoolParamsDestroy(params));
    ASSERT_SUCCESS(umfOsMemoryProviderParamsDestroy(os_memory_provider_params));
}
