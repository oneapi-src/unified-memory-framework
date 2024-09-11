// Copyright (C) 2023-2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// This file contains tests for UMF pool API

#include "ipcFixtures.hpp"

#include "provider.hpp"

#include <umf/pools/pool_disjoint.h>

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

    umf_test::provider_malloc helper_prov;
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
    const char *get_name() noexcept { return "mock_ipc"; }
    umf_result_t get_ipc_handle_size(size_t *size) noexcept {
        *size = sizeof(provider_ipc_data_t);
        return UMF_RESULT_SUCCESS;
    }
    umf_result_t get_ipc_handle(const void *ptr, size_t size,
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
    umf_result_t put_ipc_handle(void *providerIpcData) noexcept {
        (void)providerIpcData;
        return UMF_RESULT_SUCCESS;
    }
    umf_result_t open_ipc_handle(void *providerIpcData, void **ptr) noexcept {
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
    umf_result_t close_ipc_handle(void *ptr, size_t size) noexcept {
        (void)size;
        std::free(ptr);
        return UMF_RESULT_SUCCESS;
    }
};

provider_mock_ipc::allocations_mutex_type provider_mock_ipc::alloc_mutex;
provider_mock_ipc::allocations_map_type provider_mock_ipc::allocations;

static umf_memory_provider_ops_t IPC_MOCK_PROVIDER_OPS =
    umf::providerMakeCOps<provider_mock_ipc, void>();

HostMemoryAccessor hostMemoryAccessor;

INSTANTIATE_TEST_SUITE_P(umfIpcTestSuite, umfIpcTest,
                         ::testing::Values(ipcTestParams{
                             umfProxyPoolOps(), nullptr, &IPC_MOCK_PROVIDER_OPS,
                             nullptr, &hostMemoryAccessor}));
