// Copyright (C) 2025-2026 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <umf/experimental/memory_properties.h>
#include <umf/ipc.h>
#include <umf/memory_provider.h>
#include <umf/pools/pool_disjoint.h>
#include <umf/pools/pool_proxy.h>
#include <umf/providers/provider_fixed_memory.h>

#include "base.hpp"
#include "provider.hpp"
#include "test_helpers.h"
#include "utils/cpp_helpers.hpp"
#ifndef _WIN32
#include "test_helpers_linux.h"
#endif

using umf_test::test;

#define FIXED_BUFFER_SIZE (512 * utils_get_page_size())
#define INVALID_PTR ((void *)0x01)

struct TrackingProviderTest
    : umf_test::test,
      ::testing::WithParamInterface<providerCreateExtParams> {
    void SetUp() override {
        test::SetUp();

        // Allocate a memory buffer to use with the fixed memory provider
        memory_size = FIXED_BUFFER_SIZE;
        memory_buffer = malloc(memory_size);
        ASSERT_NE(memory_buffer, nullptr);

        // Create provider parameters
        umf_fixed_memory_provider_params_handle_t params = nullptr;
        umf_result_t res = umfFixedMemoryProviderParamsCreate(
            memory_buffer, memory_size, &params);
        ASSERT_EQ(res, UMF_RESULT_SUCCESS);
        ASSERT_NE(params, nullptr);

        providerCreateExt(std::make_tuple(umfFixedMemoryProviderOps(), params),
                          &provider);

        umfFixedMemoryProviderParamsDestroy(params);
        umf_result_t umf_result =
            umfMemoryProviderGetMinPageSize(provider.get(), NULL, &page_size);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

        page_plus_64 = page_size + 64;

        umf_memory_pool_handle_t hPool = nullptr;
        umf_result = umfPoolCreate(umfProxyPoolOps(), provider.get(), nullptr,
                                   0, &hPool);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

        pool = umf_test::pool_unique_handle_t(hPool, &umfPoolDestroy);
    }

    void TearDown() override {
        if (memory_buffer) {
            free(memory_buffer);
            memory_buffer = nullptr;
        }
        test::TearDown();
    }

    umf_test::provider_unique_handle_t provider;
    umf_test::pool_unique_handle_t pool;
    size_t page_size;
    size_t page_plus_64;
    void *memory_buffer = nullptr;
    size_t memory_size = 0;
};

// Helper function to create a memory pool from an existing allocation.
// If alternateAddressSpace is set to true, the pool will be created in a
// non-default address space.
static void createPoolFromAllocation(
    void *ptr0, size_t size1, umf_memory_provider_handle_t *_providerFromPtr,
    umf_memory_pool_handle_t *_poolFromPtr, bool alternateAddressSpace = false,
    const umf_memory_provider_ops_t *providerOps = umfFixedMemoryProviderOps(),
    const umf_memory_pool_ops_t *poolOps = umfProxyPoolOps(),
    const void *poolParams = nullptr) {
    umf_result_t umf_result;

    // Create provider parameters
    umf_fixed_memory_provider_params_handle_t params = nullptr;
    umf_result = umfFixedMemoryProviderParamsCreate(ptr0, size1, &params);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(params, nullptr);

    static const char namespace_token = 0;
    if (alternateAddressSpace) {
        umf_memory_provider_address_space_t addressSpace = {&namespace_token, 0,
                                                            0};
        umf_result =
            umfFixedMemoryProviderParamsSetAddressSpace(params, &addressSpace);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    }

    umf_memory_provider_handle_t provider1 = nullptr;
    umf_result = umfMemoryProviderCreate(providerOps, params, &provider1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider1, nullptr);

    umf_memory_pool_handle_t pool1 = nullptr;
    umf_result = umfPoolCreate(poolOps, provider1, poolParams, 0, &pool1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umfFixedMemoryProviderParamsDestroy(params);

    *_providerFromPtr = provider1;
    *_poolFromPtr = pool1;
}

// TESTS

INSTANTIATE_TEST_SUITE_P(trackingProviderTest, TrackingProviderTest,
                         ::testing::Values(providerCreateExtParams{
                             umfFixedMemoryProviderOps(), nullptr}),
                         providerCreateExtParamsNameGen);

TEST_P(TrackingProviderTest, create_destroy) {
    // Creation and destruction are handled in SetUp and TearDown
}

TEST_P(TrackingProviderTest, whole_size_success) {
    umf_result_t umf_result;
    size_t size0;
    size_t size1;
    void *ptr0 = nullptr;
    void *ptr1 = nullptr;

    umf_memory_pool_handle_t pool0 = pool.get();

    size0 = FIXED_BUFFER_SIZE - (2 * page_size);
    ptr0 = umfPoolAlignedMalloc(pool0, size0, utils_get_page_size());
    ASSERT_NE(ptr0, nullptr);

    size1 = size0; // whole size

    umf_memory_provider_handle_t provider1 = nullptr;
    umf_memory_pool_handle_t pool1 = nullptr;
    createPoolFromAllocation(ptr0, size1, &provider1, &pool1);

    ptr1 = umfPoolMalloc(pool1, size1);
    ASSERT_NE(ptr1, nullptr);

    for (auto query :
         {static_cast<char *>(ptr1), static_cast<char *>(ptr1) + size1 - 1}) {
        umf_memory_pool_handle_t found_pool = nullptr;
        EXPECT_EQ(umfPoolByPtr(query, &found_pool), UMF_RESULT_SUCCESS);
        EXPECT_EQ(found_pool, pool1);
        umf_memory_properties_handle_t props = nullptr;
        EXPECT_EQ(umfGetMemoryPropertiesHandle(query, &props),
                  UMF_RESULT_SUCCESS);
        EXPECT_NE(props, nullptr);
    }

    umf_result = umfPoolFree(pool1, ptr1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result = umfPoolDestroy(pool1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    umf_result = umfMemoryProviderDestroy(provider1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result = umfPoolFree(pool0, ptr0);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
}

TEST_P(TrackingProviderTest, legacy_provider_uses_default_host_address_space) {
    umf_memory_provider_ops_t legacyOps = umf_test::BA_GLOBAL_PROVIDER_OPS;
    legacyOps.get_address_space = nullptr;

    umf_memory_provider_handle_t legacyProvider = nullptr;
    ASSERT_EQ(umfMemoryProviderCreate(&legacyOps, nullptr, &legacyProvider),
              UMF_RESULT_SUCCESS);

    umf_memory_pool_handle_t legacyPool = nullptr;
    ASSERT_EQ(umfPoolCreate(umfProxyPoolOps(), legacyProvider, nullptr, 0,
                            &legacyPool),
              UMF_RESULT_SUCCESS);

    size_t size = page_size;
    void *legacyPtr = umfPoolAlignedMalloc(legacyPool, size, page_size);
    ASSERT_NE(legacyPtr, nullptr);

    umf_memory_provider_handle_t fixedProvider = nullptr;
    umf_memory_pool_handle_t fixedPool = nullptr;
    createPoolFromAllocation(legacyPtr, size, &fixedProvider, &fixedPool);

    void *fixedPtr = umfPoolMalloc(fixedPool, size);
    ASSERT_EQ(fixedPtr, legacyPtr);

    umf_memory_pool_handle_t foundPool = nullptr;
    EXPECT_EQ(umfPoolByPtr(fixedPtr, &foundPool), UMF_RESULT_SUCCESS);
    EXPECT_EQ(foundPool, fixedPool);

    EXPECT_EQ(umfPoolFree(fixedPool, fixedPtr), UMF_RESULT_SUCCESS);
    EXPECT_EQ(umfPoolDestroy(fixedPool), UMF_RESULT_SUCCESS);
    EXPECT_EQ(umfMemoryProviderDestroy(fixedProvider), UMF_RESULT_SUCCESS);
    EXPECT_EQ(umfPoolFree(legacyPool, legacyPtr), UMF_RESULT_SUCCESS);
    EXPECT_EQ(umfPoolDestroy(legacyPool), UMF_RESULT_SUCCESS);
    EXPECT_EQ(umfMemoryProviderDestroy(legacyProvider), UMF_RESULT_SUCCESS);
}

TEST_P(TrackingProviderTest, identical_address_ranges) {
    // Two pools allocate identical address ranges. Freeing through pool0 must
    // remove only its entry and leave the address associated with pool1.
    umf_memory_pool_handle_t pool0 = pool.get();
    size_t size = FIXED_BUFFER_SIZE - (2 * page_size);
    void *ptr0 = umfPoolAlignedMalloc(pool0, size, utils_get_page_size());
    ASSERT_NE(ptr0, nullptr);

    umf_memory_provider_handle_t provider1 = nullptr;
    umf_memory_pool_handle_t pool1 = nullptr;
    createPoolFromAllocation(ptr0, size, &provider1, &pool1, true);

    void *ptr1 = umfPoolMalloc(pool1, size);
    ASSERT_EQ(ptr1, ptr0);

    umf_memory_pool_handle_t found_pool = nullptr;
    umf_result_t umf_result = umfPoolByPtr(ptr0, &found_pool);
    EXPECT_EQ(umf_result, UMF_RESULT_ERROR_AMBIGUOUS);
    EXPECT_EQ(found_pool, nullptr);

    umf_result = umfPoolFree(pool0, ptr0);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    found_pool = nullptr;
    umf_result = umfPoolByPtr(ptr1, &found_pool);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    EXPECT_EQ(found_pool, pool1);

    umf_result = umfPoolFree(pool1, ptr1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result = umfPoolDestroy(pool1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    umf_result = umfMemoryProviderDestroy(provider1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
}

TEST_P(TrackingProviderTest, identical_address_ranges_umf_free) {
    // Two pools return the same address. umfFree cannot select one allocation,
    // so it must report ambiguity and leave both allocations tracked.
    umf_memory_pool_handle_t pool0 = pool.get();
    size_t size = FIXED_BUFFER_SIZE - (2 * page_size);
    void *ptr0 = umfPoolAlignedMalloc(pool0, size, utils_get_page_size());
    ASSERT_NE(ptr0, nullptr);

    umf_memory_provider_handle_t provider1 = nullptr;
    umf_memory_pool_handle_t pool1 = nullptr;
    createPoolFromAllocation(ptr0, size, &provider1, &pool1, true);

    void *ptr1 = umfPoolMalloc(pool1, size);
    ASSERT_EQ(ptr1, ptr0);

    umf_result_t umf_result = umfFree(ptr0);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_AMBIGUOUS);

    umf_memory_pool_handle_t found_pool = nullptr;
    umf_result = umfPoolByPtr(ptr1, &found_pool);
    EXPECT_EQ(umf_result, UMF_RESULT_ERROR_AMBIGUOUS);
    EXPECT_EQ(found_pool, nullptr);

    umf_result = umfPoolFree(pool1, ptr1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    umf_result = umfPoolFree(pool0, ptr0);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result = umfPoolDestroy(pool1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    umf_result = umfMemoryProviderDestroy(provider1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
}

TEST_P(TrackingProviderTest, half_size_success) {
    umf_result_t umf_result;
    size_t size0;
    size_t size1;
    void *ptr0 = nullptr;
    void *ptr1 = nullptr;

    umf_memory_pool_handle_t pool0 = pool.get();

    size0 = FIXED_BUFFER_SIZE - (2 * page_size);
    ptr0 = umfPoolAlignedMalloc(pool0, size0, utils_get_page_size());
    ASSERT_NE(ptr0, nullptr);

    size1 = size0 / 2; // half size

    umf_memory_provider_handle_t provider1 = nullptr;
    umf_memory_pool_handle_t pool1 = nullptr;
    createPoolFromAllocation(ptr0, size1, &provider1, &pool1);

    ptr1 = umfPoolMalloc(pool1, size1);
    ASSERT_NE(ptr1, nullptr);

    umf_result = umfPoolFree(pool1, ptr1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result = umfPoolDestroy(pool1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    umf_result = umfMemoryProviderDestroy(provider1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result = umfPoolFree(pool0, ptr0);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
}

TEST_P(TrackingProviderTest, failure_exceeding_size) {
    umf_result_t umf_result;
    size_t size0;
    size_t size1;
    void *ptr0 = nullptr;
    void *ptr1 = nullptr;

    umf_memory_pool_handle_t pool0 = pool.get();

    size0 = FIXED_BUFFER_SIZE - (2 * page_size);
    ptr0 = umfPoolAlignedMalloc(pool0, size0, utils_get_page_size());
    ASSERT_NE(ptr0, nullptr);

    size1 = FIXED_BUFFER_SIZE - page_size; // exceeding size

    umf_memory_provider_handle_t provider1 = nullptr;
    umf_memory_pool_handle_t pool1 = nullptr;
    createPoolFromAllocation(ptr0, size1, &provider1, &pool1);

    ptr1 = umfPoolMalloc(pool1, size1);
    ASSERT_EQ(ptr1, nullptr);

    umf_result = umfPoolDestroy(pool1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    umf_result = umfMemoryProviderDestroy(provider1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result = umfPoolFree(pool0, ptr0);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
}

TEST_P(TrackingProviderTest, partial_overlap) {
    umf_memory_pool_handle_t pool0 = pool.get();
    size_t size0 = 4 * page_size;
    void *ptr0 = umfPoolAlignedMalloc(pool0, size0, utils_get_page_size());
    ASSERT_NE(ptr0, nullptr);

    void *overlap_begin = static_cast<char *>(ptr0) + page_size;
    size_t size1 = size0;
    umf_memory_provider_handle_t provider1 = nullptr;
    umf_memory_pool_handle_t pool1 = nullptr;
    createPoolFromAllocation(overlap_begin, size1, &provider1, &pool1, true);

    void *ptr1 = umfPoolMalloc(pool1, size1);
    EXPECT_NE(ptr1, nullptr);

    if (ptr1 != nullptr) {
        umf_memory_pool_handle_t found_pool = nullptr;
        umf_result_t umf_result = umfPoolByPtr(ptr1, &found_pool);
        EXPECT_EQ(umf_result, UMF_RESULT_ERROR_AMBIGUOUS);
        EXPECT_EQ(found_pool, nullptr);

        umf_result = umfPoolFree(pool1, ptr1);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    }

    umf_result_t umf_result = umfPoolDestroy(pool1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    umf_result = umfMemoryProviderDestroy(provider1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result = umfPoolFree(pool0, ptr0);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
}

TEST_P(TrackingProviderTest, ambiguous_pointer_apis) {
    for (bool useDisjoint : {false, true}) {
        for (int addressSpaceMode : {0, 2}) {
            SCOPED_TRACE(useDisjoint);
            SCOPED_TRACE(addressSpaceMode);
            size_t parentSize = 4 * page_size;
            size_t childSize = 5 * page_size;
            void *parentPtr =
                umfPoolAlignedMalloc(pool.get(), parentSize, page_size);
            ASSERT_NE(parentPtr, nullptr);

            umf_memory_provider_ops_t ops = *umfFixedMemoryProviderOps();
            if (addressSpaceMode == 2) {
                ops.get_address_space =
                    [](void *, umf_memory_provider_address_space_t *) {
                        return UMF_RESULT_ERROR_NOT_SUPPORTED;
                    };
            }

            umf_disjoint_pool_params_handle_t poolParams = nullptr;
            if (useDisjoint) {
                ASSERT_EQ(umfDisjointPoolParamsCreate(&poolParams),
                          UMF_RESULT_SUCCESS);
                ASSERT_EQ(
                    umfDisjointPoolParamsSetMaxPoolableSize(poolParams, 0),
                    UMF_RESULT_SUCCESS);
            }

            auto childBase = static_cast<char *>(parentPtr) + page_size;
            umf_memory_provider_handle_t childProvider = nullptr;
            umf_memory_pool_handle_t childPool = nullptr;
            createPoolFromAllocation(
                childBase, childSize, &childProvider, &childPool, true, &ops,
                useDisjoint ? umfDisjointPoolOps() : umfProxyPoolOps(),
                poolParams);
            if (poolParams) {
                EXPECT_EQ(umfDisjointPoolParamsDestroy(poolParams),
                          UMF_RESULT_SUCCESS);
            }
            void *childPtr = umfPoolMalloc(childPool, childSize);
            ASSERT_EQ(childPtr, childBase);

            for (auto query :
                 {childBase, childBase + 1,
                  static_cast<char *>(parentPtr) + parentSize - 1}) {
                umf_memory_pool_handle_t foundPool = pool.get();
                EXPECT_EQ(umfPoolByPtr(query, &foundPool),
                          UMF_RESULT_ERROR_AMBIGUOUS);
                EXPECT_EQ(foundPool, pool.get());
                umf_memory_properties_handle_t props = nullptr;
                ASSERT_EQ(umfGetMemoryPropertiesHandle(parentPtr, &props),
                          UMF_RESULT_SUCCESS);
                auto originalProps = props;
                EXPECT_EQ(umfGetMemoryPropertiesHandle(query, &props),
                          UMF_RESULT_ERROR_AMBIGUOUS);
                EXPECT_EQ(props, originalProps);
                umf_ipc_handle_t ipcHandle =
                    reinterpret_cast<umf_ipc_handle_t>(query);
                size_t ipcSize = 123;
                EXPECT_EQ(umfGetIPCHandle(query, &ipcHandle, &ipcSize),
                          UMF_RESULT_ERROR_AMBIGUOUS);
                EXPECT_EQ(ipcHandle, reinterpret_cast<umf_ipc_handle_t>(query));
                EXPECT_EQ(ipcSize, 123u);
            }

            EXPECT_EQ(umfFree(childPtr), UMF_RESULT_ERROR_AMBIGUOUS);
            umf_memory_pool_handle_t foundPool = nullptr;
            EXPECT_EQ(umfPoolByPtr(parentPtr, &foundPool), UMF_RESULT_SUCCESS);
            EXPECT_EQ(foundPool, pool.get());
            EXPECT_EQ(umfPoolByPtr(static_cast<char *>(parentPtr) + parentSize,
                                   &foundPool),
                      UMF_RESULT_SUCCESS);
            EXPECT_EQ(foundPool, childPool);
            EXPECT_EQ(umfPoolByPtr(childBase + childSize, &foundPool),
                      UMF_RESULT_ERROR_INVALID_ARGUMENT);

            if (useDisjoint) {
                size_t usableSize = 0;
                EXPECT_EQ(
                    umfPoolMallocUsableSize(childPool, childPtr, &usableSize),
                    UMF_RESULT_SUCCESS);
                EXPECT_EQ(usableSize, childSize);
            }
            EXPECT_EQ(umfPoolFree(childPool, childPtr), UMF_RESULT_SUCCESS);
            EXPECT_EQ(umfPoolByPtr(childBase, &foundPool), UMF_RESULT_SUCCESS);
            EXPECT_EQ(foundPool, pool.get());
            EXPECT_EQ(umfPoolDestroy(childPool), UMF_RESULT_SUCCESS);
            EXPECT_EQ(umfMemoryProviderDestroy(childProvider),
                      UMF_RESULT_SUCCESS);
            EXPECT_EQ(umfPoolFree(pool.get(), parentPtr), UMF_RESULT_SUCCESS);
        }
    }
}

#define MAX_ARRAY 9
#define TEST_LEVEL_SUCCESS 7
#define TEST_LEVEL_FAILURE 8

TEST_P(TrackingProviderTest, success_max_levels) {
    umf_result_t umf_result;
    size_t size;
    void *ptr[MAX_ARRAY] = {0};
    umf_memory_provider_handle_t providers[MAX_ARRAY] = {0};
    umf_memory_pool_handle_t pools[MAX_ARRAY] = {0};

    size = FIXED_BUFFER_SIZE - (2 * page_size);
    pools[0] = pool.get();

    for (int i = 0; i < TEST_LEVEL_SUCCESS; i++) {
        fprintf(stderr, "Alloc #%d\n", i);
        ptr[i] = umfPoolAlignedMalloc(pools[i], size, utils_get_page_size());
        ASSERT_NE(ptr[i], nullptr);

        createPoolFromAllocation(ptr[i], size, &providers[i + 1],
                                 &pools[i + 1]);
    }

    int s = TEST_LEVEL_SUCCESS;
    fprintf(stderr, "Alloc #%d\n", s);
    ptr[s] = umfPoolAlignedMalloc(pools[s], size, utils_get_page_size());
    ASSERT_NE(ptr[s], nullptr);

    fprintf(stderr, "Free #%d\n", s);
    umf_result = umfPoolFree(pools[s], ptr[s]);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    for (int i = TEST_LEVEL_SUCCESS - 1; i >= 0; i--) {
        umf_result = umfPoolDestroy(pools[i + 1]);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        umf_result = umfMemoryProviderDestroy(providers[i + 1]);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

        fprintf(stderr, "Free #%d\n", i);
        umf_result = umfPoolFree(pools[i], ptr[i]);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    }
}

TEST_P(TrackingProviderTest, failure_exceeding_levels) {
    umf_result_t umf_result;
    size_t size;
    void *ptr[MAX_ARRAY] = {0};
    umf_memory_provider_handle_t providers[MAX_ARRAY] = {0};
    umf_memory_pool_handle_t pools[MAX_ARRAY] = {0};

    size = FIXED_BUFFER_SIZE - (2 * page_size);
    pools[0] = pool.get();

    for (int i = 0; i < TEST_LEVEL_FAILURE; i++) {
        fprintf(stderr, "Alloc #%d\n", i);
        ptr[i] = umfPoolAlignedMalloc(pools[i], size, utils_get_page_size());
        ASSERT_NE(ptr[i], nullptr);

        createPoolFromAllocation(ptr[i], size, &providers[i + 1],
                                 &pools[i + 1]);
    }

    // tracker level is too high
    int f = TEST_LEVEL_FAILURE;
    fprintf(stderr, "Alloc #%d\n", f);
    ptr[f] = umfPoolAlignedMalloc(pools[f], size, utils_get_page_size());
    ASSERT_EQ(ptr[f], nullptr);

    for (int i = TEST_LEVEL_FAILURE - 1; i >= 0; i--) {
        umf_result = umfPoolDestroy(pools[i + 1]);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        umf_result = umfMemoryProviderDestroy(providers[i + 1]);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

        fprintf(stderr, "Free #%d\n", i);
        umf_result = umfPoolFree(pools[i], ptr[i]);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    }
}

TEST_P(TrackingProviderTest, reverted_free_half_size) {
    umf_result_t umf_result;
    size_t size0;
    size_t size1;
    void *ptr0 = nullptr;
    void *ptr1 = nullptr;

    umf_memory_pool_handle_t pool0 = pool.get();

    size0 = FIXED_BUFFER_SIZE - (2 * page_size);
    ptr0 = umfPoolAlignedMalloc(pool0, size0, utils_get_page_size());
    ASSERT_NE(ptr0, nullptr);

    umf_memory_provider_handle_t provider1 = nullptr;
    umf_memory_pool_handle_t pool1 = nullptr;
    createPoolFromAllocation(ptr0, size0, &provider1, &pool1);

    size1 = size0 / 2; // half size

    ptr1 = umfPoolMalloc(pool1, size1);
    ASSERT_NE(ptr1, nullptr);

    // Freeing the "busy" pointer from the first pool is an Undefined Behavior
    // It fails now if the sizes are different.
    // see: https://github.com/oneapi-src/unified-memory-framework/pull/1161
    umf_result = umfPoolFree(pool0, ptr0);

    umf_result = umfPoolFree(pool1, ptr1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result = umfPoolDestroy(pool1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    umf_result = umfMemoryProviderDestroy(provider1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    // It could have been freed above,
    // so we cannot verify the result here.
    umf_result = umfPoolFree(pool0, ptr0);
}

TEST_P(TrackingProviderTest, reverted_free_the_same_size) {
    umf_result_t umf_result;
    size_t size0;
    size_t size1;
    void *ptr0 = nullptr;
    void *ptr1 = nullptr;

    umf_memory_pool_handle_t pool0 = pool.get();

    size0 = FIXED_BUFFER_SIZE - (2 * page_size);
    ptr0 = umfPoolAlignedMalloc(pool0, size0, utils_get_page_size());
    ASSERT_NE(ptr0, nullptr);

    umf_memory_provider_handle_t provider1 = nullptr;
    umf_memory_pool_handle_t pool1 = nullptr;
    createPoolFromAllocation(ptr0, size0, &provider1, &pool1);

    size1 = size0; // the same size

    ptr1 = umfPoolMalloc(pool1, size1);
    ASSERT_NE(ptr1, nullptr);

    // Freeing the "busy" pointer from the first pool is an Undefined Behavior
    // It succeeds now if the sizes are equal.
    // see: https://github.com/oneapi-src/unified-memory-framework/pull/1161
    umf_result = umfPoolFree(pool0, ptr0);

    // try to free the pointer from the second pool (the same size)
    umf_result = umfPoolFree(pool1, ptr1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result = umfPoolDestroy(pool1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    umf_result = umfMemoryProviderDestroy(provider1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    // It could have been freed above,
    // so we cannot verify the result here.
    umf_result = umfPoolFree(pool0, ptr0);
}
