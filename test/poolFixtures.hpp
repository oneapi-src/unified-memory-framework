// Copyright (C) 2023-2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#ifndef UMF_TEST_POOL_FIXTURES_HPP
#define UMF_TEST_POOL_FIXTURES_HPP 1

#include <array>
#include <cstring>
#include <functional>
#include <list>
#include <random>
#include <string>
#include <thread>

#include <umf/experimental/ctl.h>
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
    std::tuple<const umf_memory_pool_ops_t *, pfnPoolParamsCreate,
               pfnPoolParamsDestroy, const umf_memory_provider_ops_t *,
               pfnProviderParamsCreate, pfnProviderParamsDestroy>;

std::string poolCreateExtParamsNameGen(
    const testing::TestParamInfo<poolCreateExtParams> param) {

    const umf_memory_pool_ops_t *pool_ops = std::get<0>(param.param);
    const umf_memory_provider_ops_t *provider_ops = std::get<3>(param.param);

    const char *poolName = NULL;
    const char *providerName = NULL;

    pool_ops->get_name(NULL, &poolName);
    provider_ops->get_name(NULL, &providerName);

    std::string poolParams =
        std::get<1>(param.param)
            ? std::string("_w_params_") + std::to_string(param.index)
            : std::string("");

    return std::string(poolName) + poolParams + "_" + providerName;
}

umf_test::pool_unique_handle_t poolCreateExtUnique(poolCreateExtParams params) {
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

    return umf_test::pool_unique_handle_t(hPool, &umfPoolDestroy);
}

struct umfPoolTest : umf_test::test,
                     ::testing::WithParamInterface<poolCreateExtParams> {
    void SetUp() override {
        test::SetUp();

        pool = poolCreateExtUnique(this->GetParam());
    }

    void TearDown() override { test::TearDown(); }

    umf_test::pool_unique_handle_t pool;

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

    std::vector<umf_test::pool_unique_handle_t> pools;
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

    umf_test::pool_unique_handle_t pool;
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
    umf_result_t umf_result = umfPoolFree(pool.get(), ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
}

TEST_P(umfPoolTest, allocFreeNonAlignedSizes) {
    for (const auto &allocSize : nonAlignedAllocSizes) {
        auto *ptr = umfPoolMalloc(pool.get(), allocSize);
        ASSERT_NE(ptr, nullptr);
        std::memset(ptr, 0, allocSize);
        umf_result_t umf_result = umfPoolFree(pool.get(), ptr);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    }
}

TEST_P(umfPoolTest, allocFreeAligned) {
// ::aligned_alloc(alignment=4096, size=1) does not work under sanitizers for unknown reason
#if defined(_WIN32) || defined(__SANITIZE_ADDRESS__) ||                        \
    defined(__SANITIZE_THREAD__)
    // TODO: implement support for windows
    GTEST_SKIP();
#else
    if (!umf_test::isAlignedAllocSupported(pool.get())) {
        GTEST_SKIP();
    }

    size_t alignment = 4 * 1024; // 4kB
    void *ptr = umfPoolAlignedMalloc(pool.get(), 1, alignment);
    ASSERT_NE(ptr, nullptr);
    ASSERT_TRUE(reinterpret_cast<uintptr_t>(ptr) % alignment == 0);
    *(reinterpret_cast<unsigned char *>(ptr)) = (unsigned char)0xFF;

    umf_result_t umf_result = umfPoolFree(pool.get(), ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
#endif
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
    umf_result_t umf_result = umfPoolFree(pool.get(), new_ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
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
    umf_result_t umf_result = umfPoolFree(pool.get(), ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
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
            umf_result_t umf_result = umfPoolFree(pool, ptr);
            ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        }
    }

// ::aligned_alloc(alignment=4096, size=1) does not work under sanitizers for unknown reason
#if !defined(__SANITIZE_ADDRESS__) && !defined(__SANITIZE_THREAD__)
    // the same for size = 1
    for (size_t alignment = 1; alignment <= maxAlignment; alignment <<= 1) {
        std::vector<void *> allocs;

        for (size_t alloc = 0; alloc < numAllocs; alloc++) {
            auto *ptr = umfPoolAlignedMalloc(pool, 1, alignment);
            ASSERT_NE(ptr, nullptr);
            ASSERT_TRUE(reinterpret_cast<uintptr_t>(ptr) % alignment == 0);
            *(reinterpret_cast<unsigned char *>(ptr)) = (unsigned char)0xFF;
            allocs.push_back(ptr);
        }

        for (auto &ptr : allocs) {
            umf_result_t umf_result = umfPoolFree(pool, ptr);
            ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        }
    }
#endif
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
            umf_result_t umf_result = umfPoolFree(inPool, allocation);
            ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
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
            umf_result_t umf_result = umfPoolFree(inPool, ptr);
            ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
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
            umf_result_t umf_result = umfPoolFree(inPool, allocation);
            ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
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
            umf_result_t umf_result = umfPoolFree(inPool, allocation);
            ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
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
        umf_result_t umf_result = umfPoolFree(hPool, allocations.back());
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        allocations.pop_back();
    }

    for (int i = 0; i < expectedRecycledPoolAllocs; i++) {
        allocations.emplace_back(umfPoolMalloc(hPool, allocSize));
        ASSERT_NE(allocations.back(), nullptr);
    }

    for (auto allocation : allocations) {
        umf_result_t umf_result = umfPoolFree(hPool, allocation);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
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
        umf_memory_pool_handle_t pool = nullptr;
        auto ret = umfPoolByPtr(ptr, &pool);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        ASSERT_EQ(pool, expectedPool);

        ret = umfPoolByPtr(reinterpret_cast<void *>(
                               reinterpret_cast<intptr_t>(ptr) + size - 1),
                           &pool);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
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
    if (pool_ops == umfProxyPoolOps()) {
        GTEST_SKIP() << "Proxy pool does not support umfPoolMallocUsableSize";
    }
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
            size_t result = 0;
            umf_result_t ret =
                umfPoolMallocUsableSize(pool.get(), ptr, &result);

            ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
            ASSERT_TRUE(result == 0 || result >= allocSize);

            // Make sure we can write to this memory
            memset(ptr, 123, result);

            umf_result_t umf_result = umfPoolFree(pool.get(), ptr);
            ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
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
    umf_result = umfFixedMemoryProviderParamsCreate(
        ptr_for_pool, size_of_pool_from_ptr, &params);
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
    umf_result = umfFixedMemoryProviderParamsCreate(
        ptr_for_pool, size_of_pool_from_ptr, &params);
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

TEST_P(umfPoolTest, ctl_stat_alloc_count) {
    umf_memory_pool_handle_t pool_get = pool.get();
    const size_t size = 4096;
    const size_t max_allocs = 10;
    std::list<void *> ptrs;
    size_t alloc_count = 0;
    auto ret = umfCtlGet("umf.pool.by_handle.stats.alloc_count", pool_get,
                         &alloc_count, sizeof(alloc_count));
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(alloc_count, 0ull);
    for (size_t i = 1; i <= max_allocs; i++) {
        void *ptr = umfPoolMalloc(pool_get, size);
        ASSERT_NE(ptr, nullptr);
        ret = umfCtlGet("umf.pool.by_handle.stats.alloc_count", pool_get,
                        &alloc_count, sizeof(alloc_count));
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        ASSERT_EQ(alloc_count, i);
        ptrs.push_back(ptr);
    }

    for (auto &ptr : ptrs) {
        umf_result_t umf_result = umfPoolFree(pool_get, ptr);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    }

    ptrs.clear();
    ret = umfCtlGet("umf.pool.by_handle.stats.alloc_count", pool_get,
                    &alloc_count, sizeof(alloc_count));
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(alloc_count, 0ull);

    if (umf_test::isReallocSupported(pool_get)) {
        for (size_t i = 1; i <= max_allocs; i++) {
            void *ptr;
            if (i % 2 == 0) {
                ptr = umfPoolMalloc(pool_get, size);
            } else {
                ptr = umfPoolRealloc(pool_get, nullptr, size);
            }
            ASSERT_NE(ptr, nullptr);
            ret = umfCtlGet("umf.pool.by_handle.stats.alloc_count", pool_get,
                            &alloc_count, sizeof(alloc_count));
            ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
            ASSERT_EQ(alloc_count, i);
            ptrs.push_back(ptr);
        }
        for (auto &ptr : ptrs) {
            ptr = umfPoolRealloc(pool_get, ptr, size * 2);
            ASSERT_NE(ptr, nullptr);
        }
        ret = umfCtlGet("umf.pool.by_handle.stats.alloc_count", pool_get,
                        &alloc_count, sizeof(alloc_count));
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        ASSERT_EQ(alloc_count, max_allocs);
        size_t allocs = ptrs.size();
        for (auto &ptr : ptrs) {
            if (allocs-- % 2 == 0) {
                ptr = umfPoolRealloc(pool_get, ptr, 0);
                ASSERT_EQ(ptr, nullptr);
            } else {
                ret = umfPoolFree(pool_get, ptr);
                ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
            }
        }
        ptrs.clear();
        ret = umfCtlGet("umf.pool.by_handle.stats.alloc_count", pool_get,
                        &alloc_count, sizeof(alloc_count));
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        ASSERT_EQ(alloc_count, 0ull);
    }

    if (umf_test::isCallocSupported(pool_get)) {
        for (size_t i = 1; i <= max_allocs; i++) {
            void *ptr = umfPoolCalloc(pool_get, 1, size);
            ASSERT_NE(ptr, nullptr);
            ret = umfCtlGet("umf.pool.by_handle.stats.alloc_count", pool_get,
                            &alloc_count, sizeof(alloc_count));
            ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
            ASSERT_EQ(alloc_count, i);
            ptrs.push_back(ptr);
        }

        for (auto &ptr : ptrs) {
            umf_result_t umf_result = umfPoolFree(pool_get, ptr);
            ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        }
        ptrs.clear();
        ret = umfCtlGet("umf.pool.by_handle.stats.alloc_count", pool_get,
                        &alloc_count, sizeof(alloc_count));
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        ASSERT_EQ(alloc_count, 0ull);
    }

    if (umf_test::isAlignedAllocSupported(pool_get)) {
        for (size_t i = 1; i <= max_allocs; i++) {
            void *ptr = umfPoolAlignedMalloc(pool_get, size, 4096);
            ASSERT_NE(ptr, nullptr);
            ret = umfCtlGet("umf.pool.by_handle.stats.alloc_count", pool_get,
                            &alloc_count, sizeof(alloc_count));
            ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
            ASSERT_EQ(alloc_count, i);
            ptrs.push_back(ptr);
        }

        for (auto &ptr : ptrs) {
            umf_result_t umf_result = umfPoolFree(pool_get, ptr);
            ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        }

        ptrs.clear();
        ret = umfCtlGet("umf.pool.by_handle.stats.alloc_count", pool_get,
                        &alloc_count, sizeof(alloc_count));
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        ASSERT_EQ(alloc_count, 0ull);
    }
}
#endif /* UMF_TEST_POOL_FIXTURES_HPP */
