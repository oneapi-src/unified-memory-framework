// Copyright (C) 2024-2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#ifndef UMF_TEST_IPC_FIXTURES_HPP
#define UMF_TEST_IPC_FIXTURES_HPP

#include "base.hpp"
#include "multithread_helpers.hpp"
#include "pool.hpp"
#include "test_helpers.h"

#include <umf/ipc.h>
#include <umf/memory_pool.h>
#include <umf/memory_provider.h>
#include <umf/pools/pool_proxy.h>

#include <algorithm>
#include <cstring>
#include <numeric>
#include <random>
#include <tuple>

class MemoryAccessor {
  public:
    virtual ~MemoryAccessor() = default;
    virtual void fill(void *ptr, size_t size, const void *pattern,
                      size_t pattern_size) = 0;
    virtual void copy(void *dst_ptr, void *src_ptr, size_t size) = 0;
};

class HostMemoryAccessor : public MemoryAccessor {
  public:
    void fill(void *ptr, size_t size, const void *pattern,
              size_t pattern_size) override {
        assert(ptr != nullptr);
        assert(pattern != nullptr);
        assert(pattern_size > 0);
        while (size) {
            size_t copy_size = std::min(size, pattern_size);
            std::memcpy(ptr, pattern, copy_size);
            ptr = static_cast<char *>(ptr) + copy_size;
            size -= copy_size;
        }
    }

    void copy(void *dst_ptr, void *src_ptr, size_t size) override {
        std::memcpy(dst_ptr, src_ptr, size);
    }
};

typedef void *(*pfnPoolParamsCreate)();
typedef umf_result_t (*pfnPoolParamsDestroy)(void *);

typedef void *(*pfnProviderParamsCreate)();
typedef umf_result_t (*pfnProviderParamsDestroy)(void *);

// ipcTestParams:
// pool_ops, pfnPoolParamsCreate,pfnPoolParamsDestroy,
// provider_ops, pfnProviderParamsCreate, pfnProviderParamsDestroy,
// memoryAccessor
using ipcTestParams =
    std::tuple<const umf_memory_pool_ops_t *, pfnPoolParamsCreate,
               pfnPoolParamsDestroy, const umf_memory_provider_ops_t *,
               pfnProviderParamsCreate, pfnProviderParamsDestroy,
               MemoryAccessor *>;

struct umfIpcTest : umf_test::test,
                    ::testing::WithParamInterface<ipcTestParams> {
    umfIpcTest() {}
    size_t getOpenedIpcCacheSize() {
        const char *max_size_str = getenv("UMF_MAX_OPENED_IPC_HANDLES");
        if (max_size_str) {
            char *endptr;
            size_t max_size = strtoul(max_size_str, &endptr, 10);
            EXPECT_EQ(*endptr, '\0');
            if (*endptr == '\0') {
                return max_size;
            }
        }
        return 0;
    }
    void SetUp() override {
        test::SetUp();
        auto [pool_ops, pool_params_create, pool_params_destroy, provider_ops,
              provider_params_create, provider_params_destroy, accessor] =
            this->GetParam();
        poolOps = pool_ops;
        poolParamsCreate = pool_params_create;
        poolParamsDestroy = pool_params_destroy;
        providerOps = provider_ops;
        providerParamsCreate = provider_params_create;
        providerParamsDestroy = provider_params_destroy;
        memAccessor = accessor;
        openedIpcCacheSize = getOpenedIpcCacheSize();
        numThreads = std::max(10, (int)utils_get_num_cores());
    }

    void TearDown() override { test::TearDown(); }

    umf_test::pool_unique_handle_t makePool() {
        // TODO: The function is similar to poolCreateExt function
        //       from memoryPool.hpp
        umf_memory_provider_handle_t hProvider = NULL;
        umf_memory_pool_handle_t hPool = NULL;

        void *providerParams = nullptr;
        if (providerParamsCreate) {
            providerParams = providerParamsCreate();
        }

        auto ret =
            umfMemoryProviderCreate(providerOps, providerParams, &hProvider);
        EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

        if (providerParamsDestroy) {
            providerParamsDestroy(providerParams);
        }

        auto trace = [](void *trace_context, const char *name) {
            stats_type *stat = static_cast<stats_type *>(trace_context);
            if (std::strcmp(name, "alloc") == 0) {
                ++stat->allocCount;
            } else if (std::strcmp(name, "get_ipc_handle") == 0) {
                ++stat->getCount;
            } else if (std::strcmp(name, "put_ipc_handle") == 0) {
                ++stat->putCount;
            } else if (std::strcmp(name, "open_ipc_handle") == 0) {
                ++stat->openCount;
            } else if (std::strcmp(name, "close_ipc_handle") == 0) {
                ++stat->closeCount;
            }
        };

        umf_memory_provider_handle_t hTraceProvider =
            traceProviderCreate(hProvider, true, (void *)&stat, trace);

        void *poolParams = nullptr;
        if (poolParamsCreate) {
            poolParams = poolParamsCreate();
        }

        ret = umfPoolCreate(poolOps, hTraceProvider, poolParams,
                            UMF_POOL_CREATE_FLAG_OWN_PROVIDER, &hPool);
        EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

        if (poolParamsDestroy) {
            poolParamsDestroy(poolParams);
        }

        return umf_test::pool_unique_handle_t(hPool, &umfPoolDestroy);
    }

    struct stats_type {
        std::atomic<size_t> allocCount;
        std::atomic<size_t> getCount;
        std::atomic<size_t> putCount;
        std::atomic<size_t> openCount;
        std::atomic<size_t> closeCount;

        stats_type()
            : allocCount(0), getCount(0), putCount(0), openCount(0),
              closeCount(0) {}
    };

    unsigned int numThreads;
    static constexpr int CNTHREADS = 10;
    stats_type stat;
    MemoryAccessor *memAccessor = nullptr;

    const umf_memory_pool_ops_t *poolOps = nullptr;
    pfnPoolParamsCreate poolParamsCreate = nullptr;
    pfnPoolParamsDestroy poolParamsDestroy = nullptr;

    const umf_memory_provider_ops_t *providerOps = nullptr;
    pfnProviderParamsCreate providerParamsCreate = nullptr;
    pfnProviderParamsDestroy providerParamsDestroy = nullptr;
    size_t openedIpcCacheSize = 0;

    void concurrentGetConcurrentPutHandles(bool shuffle) {
        std::vector<void *> ptrs;
        constexpr size_t ALLOC_SIZE = 100;
        constexpr size_t NUM_POINTERS = 100;
        umf_test::pool_unique_handle_t pool = makePool();
        ASSERT_NE(pool.get(), nullptr);

        for (size_t i = 0; i < NUM_POINTERS; ++i) {
            void *ptr = umfPoolMalloc(pool.get(), ALLOC_SIZE);
            EXPECT_NE(ptr, nullptr);
            ptrs.push_back(ptr);
        }

        std::array<std::vector<umf_ipc_handle_t>, CNTHREADS> ipcHandles;

        umf_test::syncthreads_barrier syncthreads(numThreads);

        auto getHandlesFn = [shuffle, &ipcHandles, &ptrs,
                             &syncthreads](size_t tid) {
            // Each thread gets a copy of the pointers to shuffle them
            std::vector<void *> localPtrs = ptrs;
            if (shuffle) {
                std::random_device rd;
                std::mt19937 g(rd());
                std::shuffle(localPtrs.begin(), localPtrs.end(), g);
            }
            syncthreads();
            for (void *ptr : localPtrs) {
                umf_ipc_handle_t ipcHandle;
                size_t handleSize;
                umf_result_t ret =
                    umfGetIPCHandle(ptr, &ipcHandle, &handleSize);
                ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
                ipcHandles[tid].push_back(ipcHandle);
            }
        };

        umf_test::parallel_exec(numThreads, getHandlesFn);

        auto putHandlesFn = [&ipcHandles, &syncthreads](size_t tid) {
            syncthreads();
            for (umf_ipc_handle_t ipcHandle : ipcHandles[tid]) {
                umf_result_t ret = umfPutIPCHandle(ipcHandle);
                EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
            }
        };

        umf_test::parallel_exec(numThreads, putHandlesFn);

        for (void *ptr : ptrs) {
            umf_result_t ret = umfPoolFree(pool.get(), ptr);
            EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
        }

        pool.reset(nullptr);
        EXPECT_EQ(stat.putCount, stat.getCount);
    }

    void concurrentGetPutHandles(bool shuffle) {
        std::vector<void *> ptrs;
        constexpr size_t ALLOC_SIZE = 100;
        constexpr size_t NUM_POINTERS = 100;
        umf_test::pool_unique_handle_t pool = makePool();
        ASSERT_NE(pool.get(), nullptr);

        for (size_t i = 0; i < NUM_POINTERS; ++i) {
            void *ptr = umfPoolMalloc(pool.get(), ALLOC_SIZE);
            EXPECT_NE(ptr, nullptr);
            ptrs.push_back(ptr);
        }

        umf_test::syncthreads_barrier syncthreads(numThreads);

        auto getPutHandlesFn = [shuffle, &ptrs, &syncthreads](size_t) {
            // Each thread gets a copy of the pointers to shuffle them
            std::vector<void *> localPtrs = ptrs;
            if (shuffle) {
                std::random_device rd;
                std::mt19937 g(rd());
                std::shuffle(localPtrs.begin(), localPtrs.end(), g);
            }
            syncthreads();
            for (void *ptr : localPtrs) {
                umf_ipc_handle_t ipcHandle;
                size_t handleSize;
                umf_result_t ret =
                    umfGetIPCHandle(ptr, &ipcHandle, &handleSize);
                ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
                ret = umfPutIPCHandle(ipcHandle);
                EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
            }
        };

        umf_test::parallel_exec(numThreads, getPutHandlesFn);

        for (void *ptr : ptrs) {
            umf_result_t ret = umfPoolFree(pool.get(), ptr);
            EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
        }

        pool.reset(nullptr);
        EXPECT_EQ(stat.putCount, stat.getCount);
    }

    void concurrentOpenConcurrentCloseHandles(bool shuffle) {
        umf_result_t ret;
        std::vector<void *> ptrs;
        constexpr size_t ALLOC_SIZE = 100;
        constexpr size_t NUM_POINTERS = 100;
        umf_test::pool_unique_handle_t pool = makePool();
        ASSERT_NE(pool.get(), nullptr);

        for (size_t i = 0; i < NUM_POINTERS; ++i) {
            void *ptr = umfPoolMalloc(pool.get(), ALLOC_SIZE);
            EXPECT_NE(ptr, nullptr);
            ptrs.push_back(ptr);
        }

        std::vector<umf_ipc_handle_t> ipcHandles;
        for (size_t i = 0; i < NUM_POINTERS; ++i) {
            umf_ipc_handle_t ipcHandle;
            size_t handleSize;
            ret = umfGetIPCHandle(ptrs[i], &ipcHandle, &handleSize);
            ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
            ipcHandles.push_back(ipcHandle);
        }

        std::array<std::vector<void *>, CNTHREADS> openedIpcHandles;
        umf_ipc_handler_handle_t ipcHandler = nullptr;
        ret = umfPoolGetIPCHandler(pool.get(), &ipcHandler);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        ASSERT_NE(ipcHandler, nullptr);

        umf_test::syncthreads_barrier syncthreads(numThreads);

        auto openHandlesFn = [shuffle, &ipcHandles, &openedIpcHandles,
                              &syncthreads, ipcHandler](size_t tid) {
            // Each thread gets a copy of the pointers to shuffle them
            std::vector<umf_ipc_handle_t> localIpcHandles = ipcHandles;
            if (shuffle) {
                std::random_device rd;
                std::mt19937 g(rd());
                std::shuffle(localIpcHandles.begin(), localIpcHandles.end(), g);
            }
            syncthreads();
            for (auto ipcHandle : localIpcHandles) {
                void *ptr;
                umf_result_t ret =
                    umfOpenIPCHandle(ipcHandler, ipcHandle, &ptr);
                ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
                openedIpcHandles[tid].push_back(ptr);
            }
        };

        umf_test::parallel_exec(numThreads, openHandlesFn);

        auto closeHandlesFn = [&openedIpcHandles, &syncthreads](size_t tid) {
            syncthreads();
            for (void *ptr : openedIpcHandles[tid]) {
                umf_result_t ret = umfCloseIPCHandle(ptr);
                EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
            }
        };

        umf_test::parallel_exec(numThreads, closeHandlesFn);

        for (auto ipcHandle : ipcHandles) {
            ret = umfPutIPCHandle(ipcHandle);
            EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
        }

        for (void *ptr : ptrs) {
            ret = umfPoolFree(pool.get(), ptr);
            EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
        }

        pool.reset(nullptr);
        EXPECT_EQ(stat.getCount, stat.allocCount);
        EXPECT_EQ(stat.putCount, stat.getCount);
        EXPECT_EQ(stat.openCount, stat.allocCount);
        EXPECT_EQ(stat.openCount, stat.closeCount);
    }

    void concurrentOpenCloseHandles(bool shuffle) {
        umf_result_t ret;
        std::vector<void *> ptrs;
        constexpr size_t ALLOC_SIZE = 100;
        constexpr size_t NUM_POINTERS = 100;
        umf_test::pool_unique_handle_t pool = makePool();
        ASSERT_NE(pool.get(), nullptr);

        for (size_t i = 0; i < NUM_POINTERS; ++i) {
            void *ptr = umfPoolMalloc(pool.get(), ALLOC_SIZE);
            EXPECT_NE(ptr, nullptr);
            ptrs.push_back(ptr);
        }

        std::vector<umf_ipc_handle_t> ipcHandles;
        for (size_t i = 0; i < NUM_POINTERS; ++i) {
            umf_ipc_handle_t ipcHandle;
            size_t handleSize;
            ret = umfGetIPCHandle(ptrs[i], &ipcHandle, &handleSize);
            ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
            ipcHandles.push_back(ipcHandle);
        }

        umf_ipc_handler_handle_t ipcHandler = nullptr;
        ret = umfPoolGetIPCHandler(pool.get(), &ipcHandler);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        ASSERT_NE(ipcHandler, nullptr);

        umf_test::syncthreads_barrier syncthreads(numThreads);

        auto openCloseHandlesFn = [shuffle, &ipcHandles, &syncthreads,
                                   ipcHandler](size_t) {
            // Each thread gets a copy of the pointers to shuffle them
            std::vector<umf_ipc_handle_t> localIpcHandles = ipcHandles;
            if (shuffle) {
                std::random_device rd;
                std::mt19937 g(rd());
                std::shuffle(localIpcHandles.begin(), localIpcHandles.end(), g);
            }
            syncthreads();
            for (auto ipcHandle : localIpcHandles) {
                void *ptr;
                umf_result_t ret =
                    umfOpenIPCHandle(ipcHandler, ipcHandle, &ptr);
                ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
                ret = umfCloseIPCHandle(ptr);
                EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
            }
        };

        umf_test::parallel_exec(numThreads, openCloseHandlesFn);

        for (auto ipcHandle : ipcHandles) {
            ret = umfPutIPCHandle(ipcHandle);
            EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
        }

        for (void *ptr : ptrs) {
            ret = umfPoolFree(pool.get(), ptr);
            EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
        }

        pool.reset(nullptr);
        EXPECT_EQ(stat.getCount, stat.allocCount);
        EXPECT_EQ(stat.putCount, stat.getCount);
        if (openedIpcCacheSize == 0) {
            EXPECT_EQ(stat.openCount, stat.allocCount);
        }
        EXPECT_EQ(stat.openCount, stat.closeCount);
    }
};

TEST_P(umfIpcTest, GetIPCHandleSize) {
    size_t size = 0;
    umf_test::pool_unique_handle_t pool = makePool();
    ASSERT_NE(pool.get(), nullptr);

    umf_result_t ret = umfPoolGetIPCHandleSize(pool.get(), &size);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    EXPECT_GT(size, (size_t)0);
}

TEST_P(umfIpcTest, GetIPCHandleSizeInvalidArgs) {
    size_t size = 0;
    umf_result_t ret = umfPoolGetIPCHandleSize(nullptr, &size);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umf_test::pool_unique_handle_t pool = makePool();
    ASSERT_NE(pool.get(), nullptr);

    ret = umfPoolGetIPCHandleSize(pool.get(), nullptr);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_P(umfIpcTest, GetIPCHandleInvalidArgs) {
    constexpr size_t SIZE = 100;
    umf_ipc_handle_t ipcHandle = nullptr;
    size_t handleSize = 0;
    umf_result_t ret = umfGetIPCHandle(nullptr, &ipcHandle, &handleSize);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    void *ptr = (void *)0xBAD;
    ret = umfGetIPCHandle(ptr, &ipcHandle, &handleSize);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umf_test::pool_unique_handle_t pool = makePool();
    ASSERT_NE(pool.get(), nullptr);

    ptr = umfPoolMalloc(pool.get(), SIZE);
    EXPECT_NE(ptr, nullptr);

    ret = umfGetIPCHandle(ptr, nullptr, &handleSize);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = umfGetIPCHandle(ptr, &ipcHandle, nullptr);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = umfFree(ptr);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
}

TEST_P(umfIpcTest, CloseIPCHandleInvalidPtr) {
    int local_var;
    auto ret = umfCloseIPCHandle(&local_var);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_P(umfIpcTest, BasicFlow) {
    constexpr size_t SIZE = 100;
    std::vector<int> expected_data(SIZE);
    umf_test::pool_unique_handle_t pool = makePool();
    ASSERT_NE(pool.get(), nullptr);

    int *ptr = (int *)umfPoolMalloc(pool.get(), SIZE * sizeof(int));
    EXPECT_NE(ptr, nullptr);

    std::iota(expected_data.begin(), expected_data.end(), 0);
    memAccessor->copy(ptr, expected_data.data(), SIZE * sizeof(int));

    umf_ipc_handle_t ipcHandleFull = nullptr;
    size_t handleFullSize = 0;
    umf_result_t ret = umfGetIPCHandle(ptr, &ipcHandleFull, &handleFullSize);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    umf_ipc_handle_t ipcHandleHalf = nullptr;
    size_t handleHalfSize = 0;
    ret = umfGetIPCHandle(ptr + SIZE / 2, &ipcHandleHalf, &handleHalfSize);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(handleFullSize, handleHalfSize);

    umf_ipc_handler_handle_t ipcHandler = nullptr;
    ret = umfPoolGetIPCHandler(pool.get(), &ipcHandler);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(ipcHandler, nullptr);

    void *fullArray = nullptr;
    ret = umfOpenIPCHandle(ipcHandler, ipcHandleFull, &fullArray);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    void *halfArray = nullptr;
    ret = umfOpenIPCHandle(ipcHandler, ipcHandleHalf, &halfArray);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    std::vector<int> actual_data(SIZE);
    memAccessor->copy(actual_data.data(), fullArray, SIZE * sizeof(int));
    ASSERT_TRUE(std::equal(expected_data.begin(), expected_data.end(),
                           actual_data.begin()));

    // Close fullArray before reading halfArray
    ret = umfCloseIPCHandle(fullArray);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    actual_data.resize(SIZE / 2);
    memAccessor->copy(actual_data.data(), halfArray, SIZE / 2 * sizeof(int));
    ASSERT_TRUE(std::equal(expected_data.begin() + SIZE / 2,
                           expected_data.end(), actual_data.begin()));

    ret = umfCloseIPCHandle(halfArray);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfPutIPCHandle(ipcHandleFull);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfPutIPCHandle(ipcHandleHalf);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfPoolFree(pool.get(), ptr);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    pool.reset(nullptr);
    EXPECT_EQ(stat.getCount, (size_t)1);
    EXPECT_EQ(stat.putCount, stat.getCount);
    EXPECT_EQ(stat.openCount, (size_t)1);
    EXPECT_EQ(stat.closeCount, stat.openCount);
}

TEST_P(umfIpcTest, AllocFreeAllocTest) {
    constexpr size_t SIZE = 64 * 1024;
    umf_test::pool_unique_handle_t pool = makePool();
    ASSERT_NE(pool.get(), nullptr);

    umf_ipc_handler_handle_t ipcHandler = nullptr;

    umf_result_t ret = umfPoolGetIPCHandler(pool.get(), &ipcHandler);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(ipcHandler, nullptr);

    void *ptr = umfPoolMalloc(pool.get(), SIZE);
    EXPECT_NE(ptr, nullptr);

    umf_ipc_handle_t ipcHandle = nullptr;
    size_t handleSize = 0;
    ret = umfGetIPCHandle(ptr, &ipcHandle, &handleSize);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    void *opened_ptr = nullptr;
    ret = umfOpenIPCHandle(ipcHandler, ipcHandle, &opened_ptr);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfCloseIPCHandle(opened_ptr);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfPutIPCHandle(ipcHandle);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfPoolFree(pool.get(), ptr);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    ptr = umfPoolMalloc(pool.get(), SIZE);
    ASSERT_NE(ptr, nullptr);

    // test if the allocated memory is usable - fill it with the 0xAB pattern.
    const uint32_t pattern = 0xAB;
    memAccessor->fill(ptr, SIZE, &pattern, sizeof(pattern));

    ret = umfGetIPCHandle(ptr, &ipcHandle, &handleSize);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfOpenIPCHandle(ipcHandler, ipcHandle, &opened_ptr);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfCloseIPCHandle(opened_ptr);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfPutIPCHandle(ipcHandle);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfPoolFree(pool.get(), ptr);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    pool.reset(nullptr);
    EXPECT_EQ(stat.getCount, stat.putCount);
    EXPECT_EQ(stat.openCount, stat.getCount);
    EXPECT_EQ(stat.openCount, stat.closeCount);
}

TEST_P(umfIpcTest, openInTwoIpcHandlers) {
    constexpr size_t SIZE = 100;
    std::vector<int> expected_data(SIZE);
    umf_test::pool_unique_handle_t pool1 = makePool();
    ASSERT_NE(pool1.get(), nullptr);
    umf_test::pool_unique_handle_t pool2 = makePool();
    ASSERT_NE(pool2.get(), nullptr);
    umf_ipc_handler_handle_t ipcHandler1 = nullptr;
    umf_ipc_handler_handle_t ipcHandler2 = nullptr;

    umf_result_t ret = umfPoolGetIPCHandler(pool1.get(), &ipcHandler1);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(ipcHandler1, nullptr);

    ret = umfPoolGetIPCHandler(pool2.get(), &ipcHandler2);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(ipcHandler2, nullptr);

    void *ptr = umfPoolMalloc(pool1.get(), sizeof(expected_data[0]) * SIZE);
    EXPECT_NE(ptr, nullptr);

    std::iota(expected_data.begin(), expected_data.end(), 0);
    memAccessor->copy(ptr, expected_data.data(), SIZE * sizeof(int));

    umf_ipc_handle_t ipcHandle = nullptr;
    size_t handleSize = 0;
    ret = umfGetIPCHandle(ptr, &ipcHandle, &handleSize);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    void *openedPtr1 = nullptr;
    ret = umfOpenIPCHandle(ipcHandler1, ipcHandle, &openedPtr1);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    void *openedPtr2 = nullptr;
    ret = umfOpenIPCHandle(ipcHandler2, ipcHandle, &openedPtr2);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfPutIPCHandle(ipcHandle);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    std::vector<int> actual_data(SIZE);
    memAccessor->copy(actual_data.data(), openedPtr1, SIZE * sizeof(int));
    ASSERT_TRUE(std::equal(expected_data.begin(), expected_data.end(),
                           actual_data.begin()));

    ret = umfCloseIPCHandle(openedPtr1);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    memAccessor->copy(actual_data.data(), openedPtr2, SIZE * sizeof(int));
    ASSERT_TRUE(std::equal(expected_data.begin(), expected_data.end(),
                           actual_data.begin()));

    ret = umfCloseIPCHandle(openedPtr2);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfPoolFree(pool1.get(), ptr);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    pool1.reset(nullptr);
    pool2.reset(nullptr);
    EXPECT_EQ(stat.getCount, (size_t)1);
    EXPECT_EQ(stat.putCount, stat.getCount);
    EXPECT_EQ(stat.openCount, (size_t)2);
    EXPECT_EQ(stat.closeCount, stat.openCount);
}

TEST_P(umfIpcTest, ConcurrentGetConcurrentPutHandles) {
    concurrentGetConcurrentPutHandles(false);
}

TEST_P(umfIpcTest, ConcurrentGetConcurrentPutHandlesShuffled) {
    concurrentGetConcurrentPutHandles(true);
}

TEST_P(umfIpcTest, ConcurrentGetPutHandles) { concurrentGetPutHandles(false); }

TEST_P(umfIpcTest, ConcurrentGetPutHandlesShuffled) {
    concurrentGetPutHandles(true);
}

TEST_P(umfIpcTest, ConcurrentOpenConcurrentCloseHandles) {
    concurrentOpenConcurrentCloseHandles(false);
}

TEST_P(umfIpcTest, ConcurrentOpenConcurrentCloseHandlesShuffled) {
    concurrentOpenConcurrentCloseHandles(true);
}

TEST_P(umfIpcTest, ConcurrentOpenCloseHandles) {
    concurrentOpenCloseHandles(false);
}

TEST_P(umfIpcTest, ConcurrentOpenCloseHandlesShuffled) {
    concurrentOpenCloseHandles(true);
}

TEST_P(umfIpcTest, ConcurrentDestroyIpcHandlers) {
    constexpr size_t SIZE = 100;
    constexpr size_t NUM_ALLOCS = 100;
    constexpr size_t NUM_POOLS = 10;
    void *ptrs[NUM_ALLOCS];
    void *openedPtrs[NUM_POOLS][NUM_ALLOCS];
    std::vector<umf_test::pool_unique_handle_t> consumerPools;
    umf_test::pool_unique_handle_t producerPool = makePool();
    ASSERT_NE(producerPool.get(), nullptr);

    for (size_t i = 0; i < NUM_POOLS; ++i) {
        consumerPools.push_back(makePool());
        ASSERT_NE(consumerPools[i].get(), nullptr);
    }

    for (size_t i = 0; i < NUM_ALLOCS; ++i) {
        void *ptr = umfPoolMalloc(producerPool.get(), SIZE);
        ASSERT_NE(ptr, nullptr);
        ptrs[i] = ptr;
    }

    for (size_t i = 0; i < NUM_ALLOCS; ++i) {
        umf_ipc_handle_t ipcHandle = nullptr;
        size_t handleSize = 0;
        umf_result_t ret = umfGetIPCHandle(ptrs[i], &ipcHandle, &handleSize);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

        for (size_t poolId = 0; poolId < NUM_POOLS; poolId++) {
            void *ptr = nullptr;
            umf_ipc_handler_handle_t ipcHandler = nullptr;
            ret =
                umfPoolGetIPCHandler(consumerPools[poolId].get(), &ipcHandler);
            ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
            ASSERT_NE(ipcHandler, nullptr);

            ret = umfOpenIPCHandle(ipcHandler, ipcHandle, &ptr);
            ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
            openedPtrs[poolId][i] = ptr;
        }

        ret = umfPutIPCHandle(ipcHandle);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    }

    for (size_t poolId = 0; poolId < NUM_POOLS; poolId++) {
        for (size_t i = 0; i < NUM_ALLOCS; ++i) {
            umf_result_t ret = umfCloseIPCHandle(openedPtrs[poolId][i]);
            EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
        }
    }

    for (size_t i = 0; i < NUM_ALLOCS; ++i) {
        umf_result_t ret = umfFree(ptrs[i]);
        EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    }

    // Destroy pools in parallel to cause IPC cache cleanup in parallel.
    umf_test::syncthreads_barrier syncthreads(NUM_POOLS);
    auto poolDestroyFn = [&consumerPools, &syncthreads](size_t tid) {
        syncthreads();
        consumerPools[tid].reset(nullptr);
    };
    umf_test::parallel_exec(NUM_POOLS, poolDestroyFn);

    producerPool.reset(nullptr);

    EXPECT_EQ(stat.putCount, stat.getCount);
    EXPECT_EQ(stat.openCount, stat.closeCount);
}

#endif /* UMF_TEST_IPC_FIXTURES_HPP */
