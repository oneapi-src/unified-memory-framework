// Copyright (C) 2024 Intel Corporation
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

#include <cstring>
#include <numeric>
#include <tuple>

class MemoryAccessor {
  public:
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

using ipcTestParams =
    std::tuple<umf_memory_pool_ops_t *, void *, umf_memory_provider_ops_t *,
               void *, MemoryAccessor *>;

struct umfIpcTest : umf_test::test,
                    ::testing::WithParamInterface<ipcTestParams> {
    umfIpcTest() {}
    void SetUp() override { test::SetUp(); }

    void TearDown() override { test::TearDown(); }

    umf::pool_unique_handle_t makePool() {
        // TODO: The function is similar to poolCreateExt function
        //       from memoryPool.hpp
        umf_memory_provider_handle_t hProvider;
        umf_memory_pool_handle_t hPool;
        auto [pool_ops, pool_params, provider_ops, provider_params, accessor] =
            this->GetParam();

        auto ret =
            umfMemoryProviderCreate(provider_ops, provider_params, &hProvider);
        EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

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

        ret = umfPoolCreate(pool_ops, hTraceProvider, pool_params,
                            UMF_POOL_CREATE_FLAG_OWN_PROVIDER, &hPool);
        EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

        memAccessor = accessor;

        return umf::pool_unique_handle_t(hPool, &umfPoolDestroy);
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

    static constexpr int NTHREADS = 10;
    stats_type stat;
    MemoryAccessor *memAccessor = nullptr;
};

TEST_P(umfIpcTest, GetIPCHandleSize) {
    size_t size = 0;
    umf::pool_unique_handle_t pool = makePool();

    umf_result_t ret = umfPoolGetIPCHandleSize(pool.get(), &size);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    EXPECT_GT(size, 0);
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

    umf::pool_unique_handle_t pool = makePool();
    ptr = umfPoolMalloc(pool.get(), SIZE);
    EXPECT_NE(ptr, nullptr);

    ret = umfGetIPCHandle(ptr, nullptr, &handleSize);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = umfGetIPCHandle(ptr, &ipcHandle, nullptr);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = umfFree(ptr);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
}

TEST_P(umfIpcTest, BasicFlow) {
    constexpr size_t SIZE = 100;
    std::vector<int> expected_data(SIZE);
    umf::pool_unique_handle_t pool = makePool();
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

    void *fullArray = nullptr;
    ret = umfOpenIPCHandle(pool.get(), ipcHandleFull, &fullArray);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    void *halfArray = nullptr;
    ret = umfOpenIPCHandle(pool.get(), ipcHandleHalf, &halfArray);
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
    EXPECT_EQ(stat.getCount, 1);
    EXPECT_EQ(stat.putCount, stat.getCount);
    // TODO: enale check below once cache for open IPC handles is implemented
    // EXPECT_EQ(stat.openCount, 1);
    EXPECT_EQ(stat.closeCount, stat.openCount);
}

TEST_P(umfIpcTest, ConcurrentGetPutHandles) {
    std::vector<void *> ptrs;
    constexpr size_t ALLOC_SIZE = 100;
    constexpr size_t NUM_POINTERS = 100;
    umf::pool_unique_handle_t pool = makePool();

    for (size_t i = 0; i < NUM_POINTERS; ++i) {
        void *ptr = umfPoolMalloc(pool.get(), ALLOC_SIZE);
        EXPECT_NE(ptr, nullptr);
        ptrs.push_back(ptr);
    }

    std::array<std::vector<umf_ipc_handle_t>, NTHREADS> ipcHandles;

    umf_test::syncthreads_barrier syncthreads(NTHREADS);

    auto getHandlesFn = [&ipcHandles, &ptrs, &syncthreads](size_t tid) {
        syncthreads();
        for (void *ptr : ptrs) {
            umf_ipc_handle_t ipcHandle;
            size_t handleSize;
            umf_result_t ret = umfGetIPCHandle(ptr, &ipcHandle, &handleSize);
            ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
            ipcHandles[tid].push_back(ipcHandle);
        }
    };

    umf_test::parallel_exec(NTHREADS, getHandlesFn);

    auto putHandlesFn = [&ipcHandles, &syncthreads](size_t tid) {
        syncthreads();
        for (umf_ipc_handle_t ipcHandle : ipcHandles[tid]) {
            umf_result_t ret = umfPutIPCHandle(ipcHandle);
            EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
        }
    };

    umf_test::parallel_exec(NTHREADS, putHandlesFn);

    for (void *ptr : ptrs) {
        umf_result_t ret = umfPoolFree(pool.get(), ptr);
        EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    }

    pool.reset(nullptr);
    EXPECT_EQ(stat.putCount, stat.getCount);
}

TEST_P(umfIpcTest, ConcurrentOpenCloseHandles) {
    std::vector<void *> ptrs;
    constexpr size_t ALLOC_SIZE = 100;
    constexpr size_t NUM_POINTERS = 100;
    umf::pool_unique_handle_t pool = makePool();

    for (size_t i = 0; i < NUM_POINTERS; ++i) {
        void *ptr = umfPoolMalloc(pool.get(), ALLOC_SIZE);
        EXPECT_NE(ptr, nullptr);
        ptrs.push_back(ptr);
    }

    std::array<umf_ipc_handle_t, NUM_POINTERS> ipcHandles;
    for (size_t i = 0; i < NUM_POINTERS; ++i) {
        umf_ipc_handle_t ipcHandle;
        size_t handleSize;
        umf_result_t ret = umfGetIPCHandle(ptrs[i], &ipcHandle, &handleSize);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        ipcHandles[i] = ipcHandle;
    }

    std::array<std::vector<void *>, NTHREADS> openedIpcHandles;

    umf_test::syncthreads_barrier syncthreads(NTHREADS);

    auto openHandlesFn = [this, &ipcHandles, &openedIpcHandles, &syncthreads,
                          &pool](size_t tid) {
        syncthreads();
        for (auto ipcHandle : ipcHandles) {
            void *ptr;
            umf_result_t ret = umfOpenIPCHandle(pool.get(), ipcHandle, &ptr);
            ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
            openedIpcHandles[tid].push_back(ptr);
        }
    };

    umf_test::parallel_exec(NTHREADS, openHandlesFn);

    auto closeHandlesFn = [&openedIpcHandles, &syncthreads](size_t tid) {
        syncthreads();
        for (void *ptr : openedIpcHandles[tid]) {
            umf_result_t ret = umfCloseIPCHandle(ptr);
            EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
        }
    };

    umf_test::parallel_exec(NTHREADS, closeHandlesFn);

    for (auto ipcHandle : ipcHandles) {
        umf_result_t ret = umfPutIPCHandle(ipcHandle);
        EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    }

    for (void *ptr : ptrs) {
        umf_result_t ret = umfPoolFree(pool.get(), ptr);
        EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    }

    pool.reset(nullptr);
    EXPECT_EQ(stat.getCount, stat.allocCount);
    EXPECT_EQ(stat.putCount, stat.getCount);
    // TODO: enale check below once cache for open IPC handles is implemented
    // EXPECT_EQ(stat.openCount, stat.allocCount);
    EXPECT_EQ(stat.openCount, stat.closeCount);
}

#endif /* UMF_TEST_IPC_FIXTURES_HPP */
