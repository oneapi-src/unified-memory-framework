// Copyright (C) 2023-2026 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// This file contains tests for UMF pool API

#include "ipcFixtures.hpp"

#include "ipc_internal.h"
#include "provider.hpp"

#include <umf/pools/pool_disjoint.h>

#include <array>
#include <limits>
#include <shared_mutex>
#include <unordered_map>

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

    umf_test::provider_ba_global helper_prov;
    static allocations_mutex_type alloc_mutex;
    static allocations_map_type allocations;

    umf_result_t alloc(size_t size, size_t align, void **ptr) noexcept {
        auto ret = helper_prov.alloc(size, align, ptr);
        if (ret == UMF_RESULT_SUCCESS) {
            allocations_write_lock_type lock(alloc_mutex);
            auto [it, res] = allocations.emplace(*ptr, size);
            (void)it;
            EXPECT_TRUE(res);
        }
        return ret;
    }

    umf_result_t free(void *ptr, size_t size) noexcept {
        allocations_write_lock_type lock(alloc_mutex);
        allocations.erase(ptr);
        lock.unlock();
        auto ret = helper_prov.free(ptr, size);
        return ret;
    }

    umf_result_t get_name(const char **name) noexcept {
        *name = "mock_ipc";
        return UMF_RESULT_SUCCESS;
    }

    umf_result_t ext_get_ipc_handle_size(size_t *size) noexcept {
        *size = sizeof(provider_ipc_data_t);
        return UMF_RESULT_SUCCESS;
    }

    umf_result_t ext_get_ipc_handle(const void *ptr, size_t size,
                                    void *providerIpcData) noexcept {
        provider_ipc_data_t *ipcData =
            static_cast<provider_ipc_data_t *>(providerIpcData);
        // we do not need lock for allocations map here, because we just read
        // it. Inserts to allocations map are done in alloc() method that is
        // called before get_ipc_handle is called inside a parallel region.
        auto it = allocations.find(ptr);
        if (it == allocations.end() || it->second != size) {
            // client tries to get handle for the pointer that does not match
            // with any of the base addresses allocated by the instance of
            // the memory provider. Or the size argument does not match
            // the size of base allocation stored in the map
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
        ipcData->ptr = ptr;
        ipcData->size = size; // size of the base allocation
        return UMF_RESULT_SUCCESS;
    }

    umf_result_t ext_put_ipc_handle(void *providerIpcData) noexcept {
        (void)providerIpcData;
        return UMF_RESULT_SUCCESS;
    }

    umf_result_t ext_open_ipc_handle(void *providerIpcData,
                                     void **ptr) noexcept {
        provider_ipc_data_t *ipcData =
            static_cast<provider_ipc_data_t *>(providerIpcData);

        // we do not need lock for allocations map here, because we just read
        // it. Inserts to allocations map are done in alloc() method that is
        // called before get_ipc_handle is called inside a parallel region.
        auto it = allocations.find(ipcData->ptr);
        if (it == allocations.end() || it->second != ipcData->size) {
            // Since test calls open_ipc_handle in the same pool we can use
            // allocations map to validate the handle.
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }

        void *mapping = std::malloc(ipcData->size);
        if (!mapping) {
            return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        }

        memcpy(mapping, ipcData->ptr, ipcData->size);

        *ptr = mapping;

        return UMF_RESULT_SUCCESS;
    }

    umf_result_t ext_close_ipc_handle(void *ptr, size_t size) noexcept {
        (void)size;
        std::free(ptr);
        return UMF_RESULT_SUCCESS;
    }
};

provider_mock_ipc::allocations_mutex_type provider_mock_ipc::alloc_mutex;
provider_mock_ipc::allocations_map_type provider_mock_ipc::allocations;

static umf_memory_provider_ops_t IPC_MOCK_PROVIDER_OPS =
    umf_test::providerMakeCOps<provider_mock_ipc, void>();

struct provider_mock_ipc_huge_handle : public provider_mock_ipc {
    struct tracking_ipc_cache_header_t {
        uint64_t handle_id;
        uint64_t ipcDataSize;
    };

    umf_result_t get_name(const char **name) noexcept {
        *name = "mock_ipc_huge_handle";
        return UMF_RESULT_SUCCESS;
    }

    umf_result_t ext_get_ipc_handle_size(size_t *size) noexcept {
        *size = std::numeric_limits<size_t>::max() -
                sizeof(tracking_ipc_cache_header_t) + 1;
        return UMF_RESULT_SUCCESS;
    }

    umf_result_t ext_get_ipc_handle(const void *ptr, size_t size,
                                    void *providerIpcData) {
        (void)ptr;
        (void)size;
        (void)providerIpcData;
        ADD_FAILURE() << "IPC handle callback should not be called";
        return UMF_RESULT_ERROR_UNKNOWN;
    }
};

static umf_memory_provider_ops_t IPC_HUGE_HANDLE_PROVIDER_OPS =
    umf_test::providerMakeCOps<provider_mock_ipc_huge_handle, void>();

static umf_test::pool_unique_handle_t createHugeHandlePool() {
    umf_memory_provider_handle_t hProvider = nullptr;
    auto ret = umfMemoryProviderCreate(&IPC_HUGE_HANDLE_PROVIDER_OPS, nullptr,
                                       &hProvider);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    umf_memory_pool_handle_t hPool = nullptr;
    ret = umfPoolCreate(umfProxyPoolOps(), hProvider, nullptr,
                        UMF_POOL_CREATE_FLAG_OWN_PROVIDER, &hPool);
    if (ret != UMF_RESULT_SUCCESS) {
        umfMemoryProviderDestroy(hProvider);
    }
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);

    return umf_test::pool_unique_handle_t(hPool, &umfPoolDestroy);
}

struct ipcOverflowTest : umf_test::test {};

TEST_F(ipcOverflowTest, ipcHandleSizeOverflow) {
    auto pool = createHugeHandlePool();
    ASSERT_NE(pool, nullptr);

    size_t ipcHandleSize = 0;
    auto ret = umfPoolGetIPCHandleSize(pool.get(), &ipcHandleSize);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(ipcHandleSize, 0u);
}

TEST_F(ipcOverflowTest, trackingIpcCacheValueSizeOverflow) {
    auto pool = createHugeHandlePool();
    ASSERT_NE(pool, nullptr);

    void *ptr = umfPoolMalloc(pool.get(), 4096);
    ASSERT_NE(ptr, nullptr);

    umf_ipc_handler_handle_t hIPCHandler = nullptr;
    auto ret = umfPoolGetIPCHandler(pool.get(), &hIPCHandler);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(hIPCHandler, nullptr);

    alignas(umf_ipc_data_t) std::array<char, sizeof(umf_ipc_data_t) + 64>
        ipcDataBuffer{};
    auto *ipcData = reinterpret_cast<umf_ipc_data_t *>(ipcDataBuffer.data());

    ret = umfMemoryProviderGetIPCHandle(
        reinterpret_cast<umf_memory_provider_handle_t>(hIPCHandler), ptr, 4096,
        ipcData->providerIpcData);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umfPoolFree(pool.get(), ptr);
}

HostMemoryAccessor hostMemoryAccessor;

INSTANTIATE_TEST_SUITE_P(umfIpcTestSuite, umfIpcTest,
                         ::testing::Values(ipcTestParams{
                             umfProxyPoolOps(), nullptr, nullptr,
                             &IPC_MOCK_PROVIDER_OPS, nullptr, nullptr,
                             &hostMemoryAccessor}),
                         ipcTestParamsNameGen);
