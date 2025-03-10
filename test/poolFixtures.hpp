// Copyright (C) 2023-2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#ifndef UMF_TEST_POOL_FIXTURES_HPP
#define UMF_TEST_POOL_FIXTURES_HPP 1

#include <array>
#include <cstring>
#include <functional>
#include <random>
#include <string>
#include <thread>

#include <umf/pools/pool_proxy.h>
#include <umf/providers/provider_devdax_memory.h>
#include <umf/providers/provider_fixed_memory.h>

#include "../malloc_compliance_tests.hpp"
#include "pool.hpp"
#include "provider.hpp"
#include "utils/utils_sanitizers.h"

typedef void *(*pfnPoolParamsCreate)();
typedef umf_result_t (*pfnPoolParamsDestroy)(void *);

typedef void *(*pfnProviderParamsCreate)();
typedef umf_result_t (*pfnProviderParamsDestroy)(void *);

using poolCreateExtParams =
    std::tuple<umf_memory_pool_ops_t *, pfnPoolParamsCreate,
               pfnPoolParamsDestroy, umf_memory_provider_ops_t *,
               pfnProviderParamsCreate, pfnProviderParamsDestroy>;

umf::pool_unique_handle_t poolCreateExtUnique(poolCreateExtParams params) {
    auto [pool_ops, poolParamsCreate, poolParamsDestroy, provider_ops,
          providerParamsCreate, providerParamsDestroy] = params;

    umf_memory_provider_handle_t upstream_provider = nullptr;
    umf_memory_provider_handle_t provider = nullptr;
    umf_memory_pool_handle_t hPool = nullptr;
    umf_result_t ret;

    void *provider_params = NULL;
    if (providerParamsCreate) {
        provider_params = providerParamsCreate();
    }
    ret = umfMemoryProviderCreate(provider_ops, provider_params,
                                  &upstream_provider);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    EXPECT_NE(upstream_provider, nullptr);

    provider = upstream_provider;

    void *pool_params = NULL;
    if (poolParamsCreate) {
        pool_params = poolParamsCreate();
    }

    // NOTE: we set the UMF_POOL_CREATE_FLAG_OWN_PROVIDER flag here so the pool
    // will destroy the provider when it is destroyed
    ret = umfPoolCreate(pool_ops, provider, pool_params,
                        UMF_POOL_CREATE_FLAG_OWN_PROVIDER, &hPool);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    EXPECT_NE(hPool, nullptr);

    // we do not need params anymore
    if (poolParamsDestroy) {
        poolParamsDestroy(pool_params);
    }

    if (providerParamsDestroy) {
        providerParamsDestroy(provider_params);
    }

    return umf::pool_unique_handle_t(hPool, &umfPoolDestroy);
}

struct umfPoolTest : umf_test::test,
                     ::testing::WithParamInterface<poolCreateExtParams> {
    void SetUp() override {
        test::SetUp();

        pool = poolCreateExtUnique(this->GetParam());
    }

    void TearDown() override { test::TearDown(); }

    umf::pool_unique_handle_t pool;

    static constexpr int NTHREADS = 5;
    static constexpr std::array<int, 7> nonAlignedAllocSizes = {5,  7,   23, 55,
                                                                80, 119, 247};
};

struct umfMultiPoolTest : umf_test::test,
                          ::testing::WithParamInterface<poolCreateExtParams> {
    static constexpr auto numPools = 16;

    void SetUp() override {
        test::SetUp();
        for (size_t i = 0; i < numPools; i++) {
            pools.emplace_back(poolCreateExtUnique(this->GetParam()));
        }
    }

    void TearDown() override { test::TearDown(); }

    std::vector<umf::pool_unique_handle_t> pools;
};

struct umfMemTest
    : umf_test::test,
      ::testing::WithParamInterface<std::tuple<poolCreateExtParams, int>> {
    umfMemTest() : pool(nullptr, nullptr), expectedRecycledPoolAllocs(0) {}
    void SetUp() override {
        test::SetUp();

        auto [params, expRecycledPoolAllocs] = this->GetParam();
        pool = poolCreateExtUnique(params);
        expectedRecycledPoolAllocs = expRecycledPoolAllocs;
    }

    void TearDown() override { test::TearDown(); }

    umf::pool_unique_handle_t pool;
    int expectedRecycledPoolAllocs;
};

GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfMemTest);
GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfPoolTest);
GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfMultiPoolTest);

TEST_P(umfPoolTest, allocFree) {
    static constexpr size_t allocSize = 64;
    auto *ptr = umfPoolMalloc(pool.get(), allocSize);
    ASSERT_NE(ptr, nullptr);
    std::memset(ptr, 0, allocSize);
    umfPoolFree(pool.get(), ptr);
}

TEST_P(umfPoolTest, allocFreeNonAlignedSizes) {
    for (const auto &allocSize : nonAlignedAllocSizes) {
        auto *ptr = umfPoolMalloc(pool.get(), allocSize);
        ASSERT_NE(ptr, nullptr);
        std::memset(ptr, 0, allocSize);
        umfPoolFree(pool.get(), ptr);
    }
}

TEST_P(umfPoolTest, reallocFree) {
    if (!umf_test::isReallocSupported(pool.get())) {
        GTEST_SKIP();
    }
    static constexpr size_t allocSize = 64;
    static constexpr size_t multiplier = 3;
    auto *ptr = umfPoolMalloc(pool.get(), allocSize);
    ASSERT_NE(ptr, nullptr);
    memset(ptr, 0, allocSize);
    auto *new_ptr = umfPoolRealloc(pool.get(), ptr, allocSize * multiplier);
    ASSERT_NE(new_ptr, nullptr);
    std::memset(new_ptr, 0, allocSize * multiplier);
    umfPoolFree(pool.get(), new_ptr);
}

TEST_P(umfPoolTest, callocFree) {
    if (!umf_test::isCallocSupported(pool.get())) {
        GTEST_SKIP();
    }
    static constexpr size_t num = 10;
    static constexpr size_t size = sizeof(int);
    auto *ptr = umfPoolCalloc(pool.get(), num, size);
    ASSERT_NE(ptr, nullptr);
    for (size_t i = 0; i < num; ++i) {
        ASSERT_EQ(((int *)ptr)[i], 0);
    }
    umfPoolFree(pool.get(), ptr);
}

void pow2AlignedAllocHelper(umf_memory_pool_handle_t pool) {
    if (!umf_test::isAlignedAllocSupported(pool)) {
        GTEST_SKIP();
    }
    static constexpr size_t maxAlignment = (1u << 22);
    static constexpr size_t numAllocs = 4;
    for (size_t alignment = 1; alignment <= maxAlignment; alignment <<= 1) {
        std::vector<void *> allocs;

        for (size_t alloc = 0; alloc < numAllocs; alloc++) {
            auto *ptr = umfPoolAlignedMalloc(pool, alignment, alignment);
            ASSERT_NE(ptr, nullptr);
            ASSERT_TRUE(reinterpret_cast<uintptr_t>(ptr) % alignment == 0);
            std::memset(ptr, 0, alignment);
            allocs.push_back(ptr);
        }

        for (auto &ptr : allocs) {
            umfPoolFree(pool, ptr);
        }
    }
}

TEST_P(umfPoolTest, pow2AlignedAlloc) {
#ifdef _WIN32
    // TODO: implement support for windows
    GTEST_SKIP();
#else
    pow2AlignedAllocHelper(pool.get());
#endif
}

TEST_P(umfPoolTest, freeNullptr) {
    void *ptr = nullptr;
    auto ret = umfPoolFree(pool.get(), ptr);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
}

TEST_P(umfPoolTest, multiThreadedMallocFree) {
    static constexpr size_t allocSize = 64;
    auto poolMalloc = [](size_t inAllocSize, umf_memory_pool_handle_t inPool) {
        std::vector<void *> allocations;
        for (size_t i = 0; i <= 10; ++i) {
            allocations.emplace_back(umfPoolMalloc(inPool, inAllocSize));
            if (inAllocSize > 0) {
                ASSERT_NE(allocations.back(), nullptr);
            }
        }

        for (auto allocation : allocations) {
            umfPoolFree(inPool, allocation);
        }
    };

    std::vector<std::thread> threads;
    for (int i = 0; i < NTHREADS; i++) {
        threads.emplace_back(poolMalloc, allocSize, pool.get());
    }

    for (auto &thread : threads) {
        thread.join();
    }
}

TEST_P(umfPoolTest, multiThreadedpow2AlignedAlloc) {
#ifdef _WIN32
    // TODO: implement support for windows
    GTEST_SKIP();
#else
    auto poolpow2AlignedAlloc = [](umf_memory_pool_handle_t inPool) {
        pow2AlignedAllocHelper(inPool);
    };

    std::vector<std::thread> threads;
    for (int i = 0; i < NTHREADS; i++) {
        threads.emplace_back(poolpow2AlignedAlloc, pool.get());
    }

    for (auto &thread : threads) {
        thread.join();
    }
#endif
}

TEST_P(umfPoolTest, multiThreadedReallocFree) {
    if (!umf_test::isReallocSupported(pool.get())) {
        GTEST_SKIP();
    }
    static constexpr size_t allocSize = 64;
    static constexpr size_t multiplier = 3;
    auto poolRealloc = [](size_t allocSize, size_t multiplier,
                          umf_memory_pool_handle_t inPool) {
        std::vector<void *> allocations;
        for (size_t i = 0; i <= 10; ++i) {
            allocations.emplace_back(umfPoolMalloc(inPool, allocSize));
            if (allocSize > 0) {
                ASSERT_NE(allocations.back(), nullptr);
            }
        }

        for (auto allocation : allocations) {
            auto *ptr =
                umfPoolRealloc(inPool, allocation, allocSize * multiplier);
            umfPoolFree(inPool, ptr);
        }
    };

    std::vector<std::thread> threads;
    for (int i = 0; i < NTHREADS; i++) {
        threads.emplace_back(poolRealloc, allocSize, multiplier, pool.get());
    }

    for (auto &thread : threads) {
        thread.join();
    }
}

TEST_P(umfPoolTest, multiThreadedCallocFree) {
    if (!umf_test::isCallocSupported(pool.get())) {
        GTEST_SKIP();
    }
    static constexpr size_t num = 10;
    auto poolCalloc = [](size_t num, size_t size,
                         umf_memory_pool_handle_t inPool) {
        std::vector<void *> allocations;
        for (size_t i = 0; i <= 10; ++i) {
            allocations.emplace_back(umfPoolCalloc(inPool, num, size));
            if (num * size > 0) {
                ASSERT_NE(allocations.back(), nullptr);
            }
        }

        for (auto allocation : allocations) {
            umfPoolFree(inPool, allocation);
        }
    };

    std::vector<std::thread> threads;
    for (int i = 0; i < NTHREADS; i++) {
        threads.emplace_back(poolCalloc, num, sizeof(int), pool.get());
    }

    for (auto &thread : threads) {
        thread.join();
    }
}

TEST_P(umfPoolTest, multiThreadedMallocFreeRandomSizes) {
    auto poolMalloc = [](size_t allocSize, umf_memory_pool_handle_t inPool) {
        std::vector<void *> allocations;
        for (size_t i = 0; i <= 10; ++i) {
            allocations.emplace_back(umfPoolMalloc(inPool, allocSize));
            if (allocSize > 0) {
                ASSERT_NE(allocations.back(), nullptr);
            }
        }

        for (auto allocation : allocations) {
            umfPoolFree(inPool, allocation);
        }
    };

    std::vector<std::thread> threads;
    for (int i = 0; i < NTHREADS; i++) {
        threads.emplace_back(poolMalloc, (rand() % 16) * 8, pool.get());
    }

    for (auto &thread : threads) {
        thread.join();
    }
}

TEST_P(umfMemTest, outOfMem) {
    static constexpr size_t allocSize = 4096;
    auto hPool = pool.get();

    std::vector<void *> allocations;

    while (true) {
        allocations.emplace_back(umfPoolMalloc(hPool, allocSize));
        if (allocations.back() == nullptr &&
            umfPoolGetLastAllocationError(hPool) ==
                UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY) {
            break;
        }
        ASSERT_NE(allocations.back(), nullptr);
    }

    // next part of the test- freeing some memory to allocate it again (as the memory
    // should be acquired from the pool itself now, not from the provider),
    // is done only for the disjoint pool for now

    // remove last nullptr from the allocations vector
    ASSERT_EQ(allocations.back(), nullptr);
    allocations.pop_back();
    ASSERT_NE(allocations.back(), nullptr);

    for (int i = 0; i < expectedRecycledPoolAllocs; i++) {
        umfPoolFree(hPool, allocations.back());
        allocations.pop_back();
    }

    for (int i = 0; i < expectedRecycledPoolAllocs; i++) {
        allocations.emplace_back(umfPoolMalloc(hPool, allocSize));
        ASSERT_NE(allocations.back(), nullptr);
    }

    for (auto allocation : allocations) {
        umfPoolFree(hPool, allocation);
    }
}

// TODO: add similar tests for realloc/aligned_alloc, etc.
// TODO: add multithreaded tests
TEST_P(umfMultiPoolTest, memoryTracking) {
    static constexpr int allocSizes[] = {8, 16, 32, 40, 64, 128, 1024, 4096};
    static constexpr auto nAllocs = 256;

    std::mt19937_64 g(0);
    std::uniform_int_distribution allocSizesDist(
        0, static_cast<int>(std::size(allocSizes) - 1));
    std::uniform_int_distribution poolsDist(0,
                                            static_cast<int>(pools.size() - 1));

    std::vector<std::tuple<void *, size_t, umf_memory_pool_handle_t>> ptrs;
    for (size_t i = 0; i < nAllocs; i++) {
        auto &pool = pools[poolsDist(g)];
        auto size = allocSizes[allocSizesDist(g)];

        auto *ptr = umfPoolMalloc(pool.get(), size);
        ASSERT_NE(ptr, nullptr);

        ptrs.emplace_back(ptr, size, pool.get());
    }

    for (auto [ptr, size, expectedPool] : ptrs) {
        auto pool = umfPoolByPtr(ptr);
        ASSERT_EQ(pool, expectedPool);

        pool = umfPoolByPtr(reinterpret_cast<void *>(
            reinterpret_cast<intptr_t>(ptr) + size - 1));
        ASSERT_EQ(pool, expectedPool);
    }

    for (auto &p : ptrs) {
        umfFree(std::get<0>(p));
    }
}

/* malloc compliance tests */

TEST_P(umfPoolTest, malloc_compliance) { malloc_compliance_test(pool.get()); }

TEST_P(umfPoolTest, calloc_compliance) {
    if (!umf_test::isCallocSupported(pool.get())) {
        GTEST_SKIP();
    }

    calloc_compliance_test(pool.get());
}

TEST_P(umfPoolTest, realloc_compliance) {
    if (!umf_test::isReallocSupported(pool.get())) {
        GTEST_SKIP();
    }

    realloc_compliance_test(pool.get());
}

TEST_P(umfPoolTest, free_compliance) { free_compliance_test(pool.get()); }

TEST_P(umfPoolTest, allocMaxSize) {
    auto *ptr = umfPoolMalloc(pool.get(), SIZE_MAX);
    ASSERT_EQ(ptr, nullptr);
}

TEST_P(umfPoolTest, mallocUsableSize) {
    [[maybe_unused]] auto pool_ops = std::get<0>(this->GetParam());
#ifdef _WIN32
    if (pool_ops == &umf_test::MALLOC_POOL_OPS) {
        GTEST_SKIP()
            << "Windows Malloc Pool does not support umfPoolAlignedMalloc";
    }
#endif
    if (!umf_test::isAlignedAllocSupported(pool.get())) {
        GTEST_SKIP();
    }
#ifdef __SANITIZE_ADDRESS__
    if (pool_ops == &umf_test::MALLOC_POOL_OPS) {
        // Sanitizer replaces malloc_usable_size implementation with its own
        GTEST_SKIP()
            << "This test is invalid with AddressSanitizer instrumentation";
    }
#endif
    for (size_t allocSize :
         {32, 64, 1 << 6, 1 << 10, 1 << 13, 1 << 16, 1 << 19}) {
        for (size_t alignment : {0, 1 << 6, 1 << 8, 1 << 12}) {
            if (alignment >= allocSize) {
                continue;
            }
            void *ptr = nullptr;
            if (alignment == 0) {
                ptr = umfPoolMalloc(pool.get(), allocSize);
            } else {
                ptr = umfPoolAlignedMalloc(pool.get(), allocSize, alignment);
            }
            ASSERT_NE(ptr, nullptr);
            size_t result = umfPoolMallocUsableSize(pool.get(), ptr);
            ASSERT_TRUE(result == 0 || result >= allocSize);

            // Make sure we can write to this memory
            memset(ptr, 123, result);

            umfPoolFree(pool.get(), ptr);
        }
    }
}

TEST_P(umfPoolTest, umfPoolAlignedMalloc) {
#ifdef _WIN32
    // TODO: implement support for windows
    GTEST_SKIP() << "umfPoolAlignedMalloc() is not supported on Windows";
#else  /* !_WIN32 */
    umf_result_t umf_result;
    void *ptr = nullptr;
    const size_t size = 2 * 1024 * 1024; // 2MB

    umf_memory_pool_handle_t pool_get = pool.get();

    if (!umf_test::isAlignedAllocSupported(pool_get)) {
        GTEST_SKIP();
    }

    ptr = umfPoolAlignedMalloc(pool_get, size, utils_get_page_size());
    ASSERT_NE(ptr, nullptr);

    umf_result = umfPoolFree(pool_get, ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
#endif /* !_WIN32 */
}

TEST_P(umfPoolTest, pool_from_ptr_whole_size_success) {
#ifdef _WIN32
    // TODO: implement support for windows
    GTEST_SKIP() << "umfPoolAlignedMalloc() is not supported on Windows";
#else  /* !_WIN32 */
    umf_result_t umf_result;
    size_t size_of_pool_from_ptr;
    void *ptr_for_pool = nullptr;
    void *ptr = nullptr;

    umf_memory_pool_handle_t pool_get = pool.get();
    const size_t size_of_first_alloc = 2 * 1024 * 1024; // 2MB

    if (!umf_test::isAlignedAllocSupported(pool_get)) {
        GTEST_SKIP();
    }

    ptr_for_pool = umfPoolAlignedMalloc(pool_get, size_of_first_alloc,
                                        utils_get_page_size());
    ASSERT_NE(ptr_for_pool, nullptr);

    // Create provider parameters
    size_of_pool_from_ptr = size_of_first_alloc; // whole size
    umf_fixed_memory_provider_params_handle_t params = nullptr;
    umf_result = umfFixedMemoryProviderParamsCreate(&params, ptr_for_pool,
                                                    size_of_pool_from_ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(params, nullptr);

    umf_memory_provider_handle_t providerFromPtr = nullptr;
    umf_result = umfMemoryProviderCreate(umfFixedMemoryProviderOps(), params,
                                         &providerFromPtr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(providerFromPtr, nullptr);

    umf_memory_pool_handle_t poolFromPtr = nullptr;
    umf_result = umfPoolCreate(umfProxyPoolOps(), providerFromPtr, nullptr, 0,
                               &poolFromPtr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    ptr = umfPoolMalloc(poolFromPtr, size_of_pool_from_ptr);
    ASSERT_NE(ptr, nullptr);

    memset(ptr, 0xFF, size_of_pool_from_ptr);

    umf_result = umfPoolFree(poolFromPtr, ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umfPoolDestroy(poolFromPtr);
    umfMemoryProviderDestroy(providerFromPtr);
    umfFixedMemoryProviderParamsDestroy(params);

    umf_result = umfPoolFree(pool_get, ptr_for_pool);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
#endif /* !_WIN32 */
}

TEST_P(umfPoolTest, pool_from_ptr_half_size_success) {
#ifdef _WIN32
    // TODO: implement support for windows
    GTEST_SKIP() << "umfPoolAlignedMalloc() is not supported on Windows";
#else  /* !_WIN32 */
    umf_result_t umf_result;
    size_t size_of_pool_from_ptr;
    void *ptr_for_pool = nullptr;
    void *ptr = nullptr;

    umf_memory_pool_handle_t pool_get = pool.get();
    const size_t size_of_first_alloc = 2 * 1024 * 1024; // 2MB

    if (!umf_test::isAlignedAllocSupported(pool_get)) {
        GTEST_SKIP();
    }

    ptr_for_pool = umfPoolAlignedMalloc(pool_get, size_of_first_alloc,
                                        utils_get_page_size());
    ASSERT_NE(ptr_for_pool, nullptr);

    // Create provider parameters
    size_of_pool_from_ptr = size_of_first_alloc / 2; // half size
    umf_fixed_memory_provider_params_handle_t params = nullptr;
    umf_result = umfFixedMemoryProviderParamsCreate(&params, ptr_for_pool,
                                                    size_of_pool_from_ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(params, nullptr);

    umf_memory_provider_handle_t providerFromPtr = nullptr;
    umf_result = umfMemoryProviderCreate(umfFixedMemoryProviderOps(), params,
                                         &providerFromPtr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(providerFromPtr, nullptr);

    umf_memory_pool_handle_t poolFromPtr = nullptr;
    umf_result = umfPoolCreate(umfProxyPoolOps(), providerFromPtr, nullptr, 0,
                               &poolFromPtr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    ptr = umfPoolMalloc(poolFromPtr, size_of_pool_from_ptr);
    ASSERT_NE(ptr, nullptr);

    memset(ptr, 0xFF, size_of_pool_from_ptr);

    umf_result = umfPoolFree(poolFromPtr, ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umfPoolDestroy(poolFromPtr);
    umfMemoryProviderDestroy(providerFromPtr);
    umfFixedMemoryProviderParamsDestroy(params);

    umf_result = umfPoolFree(pool_get, ptr_for_pool);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
#endif /* !_WIN32 */
}

#endif /* UMF_TEST_POOL_FIXTURES_HPP */
