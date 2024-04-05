// Copyright (C) 2023-2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// This file contains tests for UMF pool API

#include "pool.hpp"
#include "provider.hpp"

#include <umf/ipc.h>
#include <umf/memory_pool.h>
#include <umf/pools/pool_proxy.h>

#include <array>
#include <atomic>
#include <cstdlib>
#include <mutex>
#include <numeric>
#include <shared_mutex>
#include <thread>
#include <unordered_map>
#include <vector>

struct provider_mock_ipc : public umf_test::provider_base_t {
    using allocations_map_type = std::unordered_map<const void *, size_t>;
    using allocations_mutex_type = std::shared_mutex;
    using allocations_read_lock_type = std::shared_lock<allocations_mutex_type>;
    using allocations_write_lock_type =
        std::unique_lock<allocations_mutex_type>;

    struct provider_ipc_data_t {
        const void *ptr;
        size_t size;
    };
    struct stats {
        std::atomic<size_t> getCount;
        std::atomic<size_t> putCount;
        std::atomic<size_t> openCount;
        std::atomic<size_t> closeCount;

        stats() : getCount(0), putCount(0), openCount(0), closeCount(0) {}
    };

    stats *stat = nullptr;
    umf_test::provider_malloc helper_prov;
    allocations_mutex_type alloc_mutex;
    allocations_map_type allocations;

    umf_result_t initialize(stats *s) noexcept {
        stat = s;
        return UMF_RESULT_SUCCESS;
    }
    enum umf_result_t alloc(size_t size, size_t align, void **ptr) noexcept {
        auto ret = helper_prov.alloc(size, align, ptr);
        if (ret == UMF_RESULT_SUCCESS) {
            allocations_write_lock_type lock(alloc_mutex);
            auto [it, res] = allocations.emplace(*ptr, size);
            (void)it;
            EXPECT_TRUE(res);
        }
        return ret;
    }
    enum umf_result_t free(void *ptr, size_t size) noexcept {
        allocations_write_lock_type lock(alloc_mutex);
        allocations.erase(ptr);
        lock.unlock();
        auto ret = helper_prov.free(ptr, size);
        return ret;
    }
    const char *get_name() noexcept { return "mock_ipc"; }
    enum umf_result_t get_ipc_handle_size(size_t *size) noexcept {
        *size = sizeof(provider_ipc_data_t);
        return UMF_RESULT_SUCCESS;
    }
    enum umf_result_t get_ipc_handle(const void *ptr, size_t size,
                                     void *providerIpcData) noexcept {
        ++stat->getCount;
        provider_ipc_data_t *ipcData =
            static_cast<provider_ipc_data_t *>(providerIpcData);
        allocations_read_lock_type lock(alloc_mutex);
        auto it = allocations.find(ptr);
        if (it == allocations.end()) {
            // client tries to get handle for the pointer that does not match
            // with any of the base addresses allocated by the instance of
            // the memory provider
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
        (void)size;
        ipcData->ptr = ptr;
        ipcData->size = it->second; // size of the base allocation
        return UMF_RESULT_SUCCESS;
    }
    enum umf_result_t put_ipc_handle(void *providerIpcData) noexcept {
        ++stat->putCount;
        (void)providerIpcData;
        return UMF_RESULT_SUCCESS;
    }
    enum umf_result_t open_ipc_handle(void *providerIpcData,
                                      void **ptr) noexcept {
        ++stat->openCount;
        provider_ipc_data_t *ipcData =
            static_cast<provider_ipc_data_t *>(providerIpcData);
        void *mapping = std::malloc(ipcData->size);
        if (!mapping) {
            return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        }

        memcpy(mapping, ipcData->ptr, ipcData->size);

        *ptr = mapping;

        return UMF_RESULT_SUCCESS;
    }
    enum umf_result_t close_ipc_handle(void *ptr) noexcept {
        ++stat->closeCount;
        std::free(ptr);
        return UMF_RESULT_SUCCESS;
    }
};

struct umfIpcTest : umf_test::test {
    umfIpcTest() : pool(nullptr, nullptr) {}
    void SetUp() override {
        test::SetUp();
        this->pool = makePool();
    }

    void TearDown() override { test::TearDown(); }

    umf::pool_unique_handle_t makePool() {
        // TODO: The function is similar to poolCreateExt function
        //       from memoryPool.hpp
        umf_memory_provider_handle_t hProvider;
        umf_memory_pool_handle_t hPool;

        auto ret =
            umfMemoryProviderCreate(&IPC_MOCK_PROVIDER_OPS, &stat, &hProvider);
        EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

        ret = umfPoolCreate(umfProxyPoolOps(), hProvider, nullptr,
                            UMF_POOL_CREATE_FLAG_OWN_PROVIDER, &hPool);
        EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

        return umf::pool_unique_handle_t(hPool, &umfPoolDestroy);
    }

    using stats_type = typename provider_mock_ipc::stats;
    umf_memory_provider_ops_t IPC_MOCK_PROVIDER_OPS =
        umf::providerMakeCOps<provider_mock_ipc, stats_type>();
    umf::pool_unique_handle_t pool;
    static constexpr int NTHREADS = 10;
    stats_type stat;
};

TEST_F(umfIpcTest, BasicFlow) {
    constexpr size_t SIZE = 100;
    int *ptr = (int *)umfPoolMalloc(pool.get(), SIZE * sizeof(int));
    EXPECT_NE(ptr, nullptr);

    std::iota(ptr, ptr + SIZE, 0);

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

    for (int i = 0; i < (int)SIZE; ++i) {
        ASSERT_EQ(reinterpret_cast<int *>(fullArray)[i], i);
    }
    // Close fullArray before reading halfArray
    ret = umfCloseIPCHandle(fullArray);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    for (int i = 0; i < (int)SIZE / 2; ++i) {
        ASSERT_EQ(reinterpret_cast<int *>(halfArray)[i], i + SIZE / 2);
    }
    ret = umfCloseIPCHandle(halfArray);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfPutIPCHandle(ipcHandleFull);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfPutIPCHandle(ipcHandleHalf);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfPoolFree(pool.get(), ptr);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    EXPECT_EQ(stat.getCount, 1);
    EXPECT_EQ(stat.putCount, stat.getCount);
    // TODO: enale check below once cache for open IPC handles is implemented
    // EXPECT_EQ(stat.openCount, 1);
    EXPECT_EQ(stat.closeCount, stat.openCount);
}

TEST_F(umfIpcTest, ConcurrentGetPutHandles) {
    std::vector<void *> ptrs;
    constexpr size_t ALLOC_SIZE = 100;
    constexpr size_t NUM_POINTERS = 100;
    for (size_t i = 0; i < NUM_POINTERS; ++i) {
        void *ptr = umfPoolMalloc(pool.get(), ALLOC_SIZE);
        EXPECT_NE(ptr, nullptr);
        ptrs.push_back(ptr);
    }

    std::array<std::vector<umf_ipc_handle_t>, NTHREADS> ipcHandles;

    auto getHandlesFn = [&ipcHandles, &ptrs](size_t tid) {
        // TODO: better to wait on the barrier here so that every thread
        // starts at the same point. But std::barrier is available only
        // starting from C++20
        for (void *ptr : ptrs) {
            umf_ipc_handle_t ipcHandle;
            size_t handleSize;
            umf_result_t ret = umfGetIPCHandle(ptr, &ipcHandle, &handleSize);
            ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
            ipcHandles[tid].push_back(ipcHandle);
        }
    };

    std::vector<std::thread> threads;
    for (int i = 0; i < NTHREADS; i++) {
        threads.emplace_back(getHandlesFn, i);
    }

    for (auto &thread : threads) {
        thread.join();
    }
    threads.clear();

    auto putHandlesFn = [&ipcHandles](size_t tid) {
        for (umf_ipc_handle_t ipcHandle : ipcHandles[tid]) {
            umf_result_t ret = umfPutIPCHandle(ipcHandle);
            EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
        }
    };

    for (int i = 0; i < NTHREADS; i++) {
        threads.emplace_back(putHandlesFn, i);
    }

    for (auto &thread : threads) {
        thread.join();
    }
    threads.clear();

    for (void *ptr : ptrs) {
        umf_result_t ret = umfPoolFree(pool.get(), ptr);
        EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    }

    EXPECT_GE(stat.getCount, NUM_POINTERS);
    EXPECT_LE(stat.getCount, NUM_POINTERS * NTHREADS);
    EXPECT_EQ(stat.putCount, stat.getCount);
}

TEST_F(umfIpcTest, ConcurrentOpenCloseHandles) {
    std::vector<void *> ptrs;
    constexpr size_t ALLOC_SIZE = 100;
    constexpr size_t NUM_POINTERS = 100;
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

    auto openHandlesFn = [this, &ipcHandles, &openedIpcHandles](size_t tid) {
        // TODO: better to wait on the barrier here so that every thread
        // starts at the same point. But std::barrier is available only
        // starting from C++20
        for (auto ipcHandle : ipcHandles) {
            void *ptr;
            umf_result_t ret = umfOpenIPCHandle(pool.get(), ipcHandle, &ptr);
            ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
            openedIpcHandles[tid].push_back(ptr);
        }
    };

    std::vector<std::thread> threads;
    for (int i = 0; i < NTHREADS; i++) {
        threads.emplace_back(openHandlesFn, i);
    }

    for (auto &thread : threads) {
        thread.join();
    }
    threads.clear();

    auto closeHandlesFn = [&openedIpcHandles](size_t tid) {
        for (void *ptr : openedIpcHandles[tid]) {
            umf_result_t ret = umfCloseIPCHandle(ptr);
            EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
        }
    };

    for (int i = 0; i < NTHREADS; i++) {
        threads.emplace_back(closeHandlesFn, i);
    }

    for (auto &thread : threads) {
        thread.join();
    }
    threads.clear();

    for (auto ipcHandle : ipcHandles) {
        umf_result_t ret = umfPutIPCHandle(ipcHandle);
        EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    }

    for (void *ptr : ptrs) {
        umf_result_t ret = umfPoolFree(pool.get(), ptr);
        EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    }

    EXPECT_EQ(stat.openCount, stat.closeCount);
}
