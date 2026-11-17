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
#include "ipc_internal.h"
#include "provider.hpp"
#include "provider/provider_tracking.h"
#include "test_helpers.h"
#include "utils/cpp_helpers.hpp"
#ifndef _WIN32
#include "test_helpers_linux.h"
#endif

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

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

struct tracking_ipc_test_state {
    std::mutex mutex;
    std::condition_variable cv;
    bool block_get = false;
    bool release_get = false;
    bool get_entered = false;
    bool block_size = false;
    bool release_size = false;
    bool size_entered = false;
    bool block_free = false;
    bool release_free = false;
    void *reuse_ptr = nullptr;
    int failures_remaining = 0;
    umf_result_t failure_result = UMF_RESULT_ERROR_UNKNOWN;
    size_t size_calls = 0;
    size_t get_calls = 0;
    size_t put_calls = 0;
    size_t free_calls = 0;
    std::vector<uint64_t> put_handles;
};

struct tracking_ipc_test_params {
    tracking_ipc_test_state *state;
};

static thread_local int tracking_ipc_test_native_error = -1;

struct tracking_ipc_test_provider : public umf_test::provider_base_t {
    umf_test::provider_ba_global helper;
    tracking_ipc_test_state *state = nullptr;

    umf_result_t initialize(const tracking_ipc_test_params *params) noexcept {
        state = params->state;
        return UMF_RESULT_SUCCESS;
    }

    umf_result_t alloc(size_t size, size_t alignment, void **ptr) noexcept {
        if (state->reuse_ptr) {
            *ptr = state->reuse_ptr;
            return UMF_RESULT_SUCCESS;
        }
        return helper.alloc(size, alignment, ptr);
    }

    umf_result_t free(void *ptr, size_t size) noexcept {
        {
            std::unique_lock<std::mutex> lock(state->mutex);
            ++state->free_calls;
            state->cv.notify_all();
            if (state->block_free &&
                !state->cv.wait_for(lock, std::chrono::seconds(10),
                                    [this] { return state->release_free; })) {
                return UMF_RESULT_ERROR_UNKNOWN;
            }
        }
        if (state->reuse_ptr) {
            return UMF_RESULT_SUCCESS;
        }
        return helper.free(ptr, size);
    }

    umf_result_t get_last_native_error(const char **message,
                                       int32_t *error) noexcept {
        *message = "tracking IPC mock error";
        *error = tracking_ipc_test_native_error;
        return UMF_RESULT_SUCCESS;
    }

    umf_result_t get_name(const char **name) noexcept {
        *name = "tracking_ipc_test";
        return UMF_RESULT_SUCCESS;
    }

    umf_result_t ext_get_ipc_handle_size(size_t *size) noexcept {
        {
            std::unique_lock<std::mutex> lock(state->mutex);
            ++state->size_calls;
            state->size_entered = true;
            state->cv.notify_all();
            if (state->block_size) {
                state->cv.wait_for(lock, std::chrono::seconds(10),
                                   [this] { return state->release_size; });
            }
        }
        *size = sizeof(uint64_t);
        return UMF_RESULT_SUCCESS;
    }

    umf_result_t ext_get_ipc_handle(const void *, size_t,
                                    void *providerIpcData) noexcept {
        if (reinterpret_cast<std::uintptr_t>(providerIpcData) %
                alignof(uint64_t) !=
            0) {
            return UMF_RESULT_ERROR_UNKNOWN;
        }

        umf_result_t result = UMF_RESULT_SUCCESS;
        uint64_t handle = 0;
        {
            std::unique_lock<std::mutex> lock(state->mutex);
            handle = ++state->get_calls;
            state->get_entered = true;
            state->cv.notify_all();
            if (state->block_get) {
                state->cv.wait_for(lock, std::chrono::seconds(10),
                                   [this] { return state->release_get; });
            }
            if (state->failures_remaining > 0) {
                --state->failures_remaining;
                result = state->failure_result;
            }
        }

        if (result == UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC) {
            tracking_ipc_test_native_error = 1234;
            return result;
        }
        if (result != UMF_RESULT_SUCCESS) {
            return result;
        }

        tracking_ipc_test_native_error = -1;
        *static_cast<uint64_t *>(providerIpcData) = handle;
        return UMF_RESULT_SUCCESS;
    }

    umf_result_t ext_put_ipc_handle(void *providerIpcData) noexcept {
        if (!state) {
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
        std::lock_guard<std::mutex> lock(state->mutex);
        ++state->put_calls;
        state->put_handles.push_back(*static_cast<uint64_t *>(providerIpcData));
        return UMF_RESULT_SUCCESS;
    }
};

static umf_memory_provider_ops_t TRACKING_IPC_TEST_PROVIDER_OPS =
    umf_test::providerMakeCOps<tracking_ipc_test_provider,
                               tracking_ipc_test_params>();

struct tracking_ipc_get_result {
    umf_result_t result = UMF_RESULT_ERROR_UNKNOWN;
    std::vector<uint64_t> storage;
    uint64_t handle_id = 0;
    uint64_t provider_data = 0;
    int native_error = -1;
};

static tracking_ipc_get_result
tracking_ipc_get(void *ptr, size_t allocation_size, size_t ipc_handle_size,
                 umf_memory_provider_handle_t tracking_provider,
                 umf_memory_provider_handle_t upstream_provider) {
    tracking_ipc_get_result result;
    result.storage.resize(
        (ipc_handle_size + sizeof(umf_ipc_data_t) + sizeof(uint64_t) - 1) /
        sizeof(uint64_t));
    auto *ipc_data = reinterpret_cast<umf_ipc_data_t *>(result.storage.data());
    result.result = umfMemoryProviderGetIPCHandle(
        tracking_provider, ptr, allocation_size, ipc_data->providerIpcData);
    result.handle_id = ipc_data->handle_id;
    result.provider_data =
        *reinterpret_cast<uint64_t *>(ipc_data->providerIpcData);
    if (result.result == UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC) {
        const char *message = nullptr;
        int32_t error = -1;
        umfMemoryProviderGetLastNativeError(upstream_provider, &message,
                                            &error);
        result.native_error = error;
    }
    return result;
}

static bool
wait_for_tracking_ipc_waiters(umf_memory_provider_handle_t tracking_provider,
                              void *ptr, size_t expected_waiters) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        if (umfTrackingMemoryProviderGetIpcCacheWaiterCount(
                tracking_provider, ptr) >= expected_waiters) {
            return true;
        }
        std::this_thread::yield();
    }
    return false;
}

static bool
wait_for_tracking_ipc_state(tracking_ipc_test_state &state,
                            const std::function<bool()> &predicate) {
    std::unique_lock<std::mutex> lock(state.mutex);
    return state.cv.wait_for(lock, std::chrono::seconds(5), predicate);
}

static void release_tracking_ipc_get(tracking_ipc_test_state &state) {
    std::lock_guard<std::mutex> lock(state.mutex);
    state.release_get = true;
    state.cv.notify_all();
}

static void release_tracking_ipc_size(tracking_ipc_test_state &state) {
    std::lock_guard<std::mutex> lock(state.mutex);
    state.release_size = true;
    state.cv.notify_all();
}

static umf_result_t
create_tracking_ipc_test_pool(tracking_ipc_test_state *state,
                              umf_memory_provider_handle_t *provider,
                              umf_memory_pool_handle_t *pool) {
    tracking_ipc_test_params params{state};
    umf_result_t ret = umfMemoryProviderCreate(&TRACKING_IPC_TEST_PROVIDER_OPS,
                                               &params, provider);
    if (ret != UMF_RESULT_SUCCESS) {
        return ret;
    }

    ret = umfPoolCreate(umfProxyPoolOps(), *provider, nullptr, 0, pool);
    if (ret != UMF_RESULT_SUCCESS) {
        umfMemoryProviderDestroy(*provider);
        *provider = nullptr;
    }
    return ret;
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

TEST(TrackingProviderIpcConcurrencyTest, concurrent_get_is_single_flight) {
    tracking_ipc_test_state state;
    umf_memory_provider_handle_t raw_provider = nullptr;
    umf_memory_pool_handle_t raw_pool = nullptr;
    ASSERT_EQ(create_tracking_ipc_test_pool(&state, &raw_provider, &raw_pool),
              UMF_RESULT_SUCCESS);
    umf_test::provider_unique_handle_t provider(raw_provider,
                                                &umfMemoryProviderDestroy);
    umf_test::pool_unique_handle_t pool(raw_pool, &umfPoolDestroy);
    umf_ipc_handler_handle_t raw_tracking_provider = nullptr;
    ASSERT_EQ(umfPoolGetIPCHandler(pool.get(), &raw_tracking_provider),
              UMF_RESULT_SUCCESS);
    auto tracking_provider =
        reinterpret_cast<umf_memory_provider_handle_t>(raw_tracking_provider);
    size_t ipc_handle_size = 0;
    ASSERT_EQ(
        umfMemoryProviderGetIPCHandleSize(tracking_provider, &ipc_handle_size),
        UMF_RESULT_SUCCESS);

    void *ptr = umfPoolMalloc(pool.get(), 128);
    ASSERT_NE(ptr, nullptr);
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        state.block_get = true;
    }

    constexpr size_t WAITER_COUNT = 4;
    std::array<tracking_ipc_get_result, WAITER_COUNT + 1> results;
    std::array<std::thread, WAITER_COUNT + 1> callers;
    callers[0] = std::thread([&] {
        results[0] = tracking_ipc_get(ptr, 128, ipc_handle_size,
                                      tracking_provider, provider.get());
    });

    bool entered =
        wait_for_tracking_ipc_state(state, [&] { return state.get_entered; });
    for (size_t i = 0; i < WAITER_COUNT; ++i) {
        callers[i + 1] = std::thread([&, i] {
            results[i + 1] = tracking_ipc_get(
                ptr, 128, ipc_handle_size, tracking_provider, provider.get());
        });
    }
    bool waiters_joined =
        wait_for_tracking_ipc_waiters(tracking_provider, ptr, WAITER_COUNT);
    release_tracking_ipc_get(state);
    for (auto &caller : callers) {
        caller.join();
    }

    ASSERT_TRUE(entered);
    ASSERT_TRUE(waiters_joined);
    for (const auto &result : results) {
        ASSERT_EQ(result.result, UMF_RESULT_SUCCESS);
        EXPECT_EQ(result.handle_id, results[0].handle_id);
        EXPECT_EQ(result.provider_data, results[0].provider_data);
    }
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        EXPECT_EQ(state.get_calls, 1u);
        EXPECT_EQ(state.put_calls, 0u);
    }

    EXPECT_EQ(umfPoolFree(pool.get(), ptr), UMF_RESULT_SUCCESS);
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        EXPECT_EQ(state.put_calls, 1u);
    }
}

TEST(TrackingProviderIpcConcurrencyTest,
     failed_get_error_is_thread_local_and_retry_succeeds) {
    tracking_ipc_test_state state;
    state.block_get = true;
    state.failures_remaining = 1;
    state.failure_result = UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    umf_memory_provider_handle_t raw_provider = nullptr;
    umf_memory_pool_handle_t raw_pool = nullptr;
    ASSERT_EQ(create_tracking_ipc_test_pool(&state, &raw_provider, &raw_pool),
              UMF_RESULT_SUCCESS);
    umf_test::provider_unique_handle_t provider(raw_provider,
                                                &umfMemoryProviderDestroy);
    umf_test::pool_unique_handle_t pool(raw_pool, &umfPoolDestroy);
    umf_ipc_handler_handle_t raw_tracking_provider = nullptr;
    ASSERT_EQ(umfPoolGetIPCHandler(pool.get(), &raw_tracking_provider),
              UMF_RESULT_SUCCESS);
    auto tracking_provider =
        reinterpret_cast<umf_memory_provider_handle_t>(raw_tracking_provider);
    size_t ipc_handle_size = 0;
    ASSERT_EQ(
        umfMemoryProviderGetIPCHandleSize(tracking_provider, &ipc_handle_size),
        UMF_RESULT_SUCCESS);

    void *ptr = umfPoolMalloc(pool.get(), 128);
    ASSERT_NE(ptr, nullptr);
    tracking_ipc_get_result creator_result;
    tracking_ipc_get_result waiter_result;
    std::thread creator([&] {
        creator_result = tracking_ipc_get(ptr, 128, ipc_handle_size,
                                          tracking_provider, provider.get());
    });
    bool entered =
        wait_for_tracking_ipc_state(state, [&] { return state.get_entered; });
    std::thread waiter([&] {
        waiter_result = tracking_ipc_get(ptr, 128, ipc_handle_size,
                                         tracking_provider, provider.get());
    });
    bool waiter_joined =
        wait_for_tracking_ipc_waiters(tracking_provider, ptr, 1);
    release_tracking_ipc_get(state);
    creator.join();
    waiter.join();

    ASSERT_TRUE(entered);
    ASSERT_TRUE(waiter_joined);
    EXPECT_EQ(creator_result.result, UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC);
    EXPECT_EQ(creator_result.native_error, 1234);
    EXPECT_EQ(waiter_result.result, UMF_RESULT_ERROR_UNKNOWN);
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        EXPECT_EQ(state.get_calls, 1u);
    }

    tracking_ipc_get_result retry_result = tracking_ipc_get(
        ptr, 128, ipc_handle_size, tracking_provider, provider.get());
    ASSERT_EQ(retry_result.result, UMF_RESULT_SUCCESS);
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        EXPECT_EQ(state.get_calls, 2u);
    }

    EXPECT_EQ(umfPoolFree(pool.get(), ptr), UMF_RESULT_SUCCESS);
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        EXPECT_EQ(state.put_calls, 1u);
    }
}

TEST(TrackingProviderIpcConcurrencyTest, failed_get_preserves_retiring_entry) {
    std::array<uint64_t, 16> allocation;
    tracking_ipc_test_state state;
    state.reuse_ptr = allocation.data();
    state.block_get = true;
    state.block_free = true;
    state.failures_remaining = 1;
    umf_memory_provider_handle_t raw_provider = nullptr;
    umf_memory_pool_handle_t raw_pool = nullptr;
    ASSERT_EQ(create_tracking_ipc_test_pool(&state, &raw_provider, &raw_pool),
              UMF_RESULT_SUCCESS);
    umf_test::provider_unique_handle_t provider(raw_provider,
                                                &umfMemoryProviderDestroy);
    umf_test::pool_unique_handle_t pool(raw_pool, &umfPoolDestroy);
    umf_ipc_handler_handle_t handler = nullptr;
    ASSERT_EQ(umfPoolGetIPCHandler(pool.get(), &handler), UMF_RESULT_SUCCESS);
    auto tracking_provider =
        reinterpret_cast<umf_memory_provider_handle_t>(handler);
    size_t ipc_handle_size = 0;
    ASSERT_EQ(
        umfMemoryProviderGetIPCHandleSize(tracking_provider, &ipc_handle_size),
        UMF_RESULT_SUCCESS);
    void *ptr = umfPoolMalloc(pool.get(), sizeof(allocation));
    ASSERT_EQ(ptr, allocation.data());

    tracking_ipc_get_result creator_result;
    std::thread creator([&] {
        creator_result =
            tracking_ipc_get(ptr, sizeof(allocation), ipc_handle_size,
                             tracking_provider, provider.get());
    });
    bool get_entered =
        wait_for_tracking_ipc_state(state, [&] { return state.get_entered; });
    umf_result_t free_result = UMF_RESULT_ERROR_UNKNOWN;
    std::thread freer([&] { free_result = umfPoolFree(pool.get(), ptr); });
    bool free_waiting =
        wait_for_tracking_ipc_waiters(tracking_provider, ptr, 1);
    release_tracking_ipc_get(state);
    creator.join();
    bool free_entered = wait_for_tracking_ipc_state(
        state, [&] { return state.free_calls == 1; });

    auto rejected_result =
        tracking_ipc_get(ptr, sizeof(allocation), ipc_handle_size,
                         tracking_provider, provider.get());
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        EXPECT_EQ(state.get_calls, 1u);
        EXPECT_EQ(state.put_calls, 0u);
        state.release_free = true;
        state.cv.notify_all();
    }
    freer.join();

    ASSERT_TRUE(get_entered);
    ASSERT_TRUE(free_waiting);
    ASSERT_TRUE(free_entered);
    EXPECT_EQ(creator_result.result, UMF_RESULT_ERROR_UNKNOWN);
    EXPECT_EQ(rejected_result.result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(free_result, UMF_RESULT_SUCCESS);

    void *reused_ptr = umfPoolMalloc(pool.get(), sizeof(allocation));
    ASSERT_EQ(reused_ptr, ptr);
    auto retry_result =
        tracking_ipc_get(reused_ptr, sizeof(allocation), ipc_handle_size,
                         tracking_provider, provider.get());
    EXPECT_EQ(retry_result.result, UMF_RESULT_SUCCESS);
    EXPECT_NE(retry_result.handle_id, 0u);
    EXPECT_EQ(umfPoolFree(pool.get(), reused_ptr), UMF_RESULT_SUCCESS);
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        EXPECT_EQ(state.get_calls, 2u);
        EXPECT_EQ(state.put_calls, 1u);
        EXPECT_EQ(state.free_calls, 2u);
    }
}

TEST(TrackingProviderIpcConcurrencyTest, delayed_get_rejects_freed_allocation) {
    std::array<uint64_t, 16> allocation;
    tracking_ipc_test_state state;
    state.reuse_ptr = allocation.data();
    umf_memory_provider_handle_t raw_provider = nullptr;
    umf_memory_pool_handle_t raw_pool = nullptr;
    ASSERT_EQ(create_tracking_ipc_test_pool(&state, &raw_provider, &raw_pool),
              UMF_RESULT_SUCCESS);
    umf_test::provider_unique_handle_t provider(raw_provider,
                                                &umfMemoryProviderDestroy);
    umf_test::pool_unique_handle_t pool(raw_pool, &umfPoolDestroy);
    umf_ipc_handler_handle_t handler = nullptr;
    ASSERT_EQ(umfPoolGetIPCHandler(pool.get(), &handler), UMF_RESULT_SUCCESS);
    auto tracking_provider =
        reinterpret_cast<umf_memory_provider_handle_t>(handler);
    size_t ipc_handle_size = 0;
    ASSERT_EQ(
        umfMemoryProviderGetIPCHandleSize(tracking_provider, &ipc_handle_size),
        UMF_RESULT_SUCCESS);
    void *ptr = umfPoolMalloc(pool.get(), sizeof(allocation));
    ASSERT_EQ(ptr, allocation.data());
    auto original = tracking_ipc_get(ptr, sizeof(allocation), ipc_handle_size,
                                     tracking_provider, provider.get());
    ASSERT_EQ(original.result, UMF_RESULT_SUCCESS);

    std::mutex gate;
    std::condition_variable cv;
    bool started = false;
    bool resume = false;
    tracking_ipc_get_result delayed;
    std::thread getter([&] {
        {
            std::unique_lock<std::mutex> lock(gate);
            started = true;
            cv.notify_all();
            // Pause before the provider's first cache lookup, without
            // retaining any allocation metadata across Free.
            cv.wait(lock, [&] { return resume; });
        }
        delayed = tracking_ipc_get(ptr, sizeof(allocation), ipc_handle_size,
                                   tracking_provider, provider.get());
    });
    {
        std::unique_lock<std::mutex> lock(gate);
        cv.wait(lock, [&] { return started; });
    }
    EXPECT_EQ(umfPoolFree(pool.get(), ptr), UMF_RESULT_SUCCESS);
    {
        std::lock_guard<std::mutex> lock(gate);
        resume = true;
        cv.notify_all();
    }
    getter.join();
    EXPECT_EQ(delayed.result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        EXPECT_EQ(state.get_calls, 1u);
        EXPECT_EQ(state.put_calls, 1u);
    }

    void *reused_ptr = umfPoolMalloc(pool.get(), sizeof(allocation));
    ASSERT_EQ(reused_ptr, ptr);
    auto replacement =
        tracking_ipc_get(reused_ptr, sizeof(allocation), ipc_handle_size,
                         tracking_provider, provider.get());
    EXPECT_EQ(replacement.result, UMF_RESULT_SUCCESS);
    EXPECT_NE(replacement.handle_id, original.handle_id);
    EXPECT_NE(replacement.provider_data, original.provider_data);
    EXPECT_EQ(umfPoolFree(pool.get(), reused_ptr), UMF_RESULT_SUCCESS);
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        EXPECT_EQ(state.get_calls, 2u);
        EXPECT_EQ(state.put_handles,
                  (std::vector<uint64_t>{original.provider_data,
                                         replacement.provider_data}));
    }
}

TEST(TrackingProviderIpcConcurrencyTest, old_free_preserves_replacement_entry) {
    std::array<uint64_t, 16> allocation;
    tracking_ipc_test_state state;
    state.reuse_ptr = allocation.data();
    state.block_free = true;
    umf_memory_provider_handle_t raw_provider = nullptr;
    umf_memory_pool_handle_t raw_pool = nullptr;
    ASSERT_EQ(create_tracking_ipc_test_pool(&state, &raw_provider, &raw_pool),
              UMF_RESULT_SUCCESS);
    umf_test::provider_unique_handle_t provider(raw_provider,
                                                &umfMemoryProviderDestroy);
    umf_test::pool_unique_handle_t pool(raw_pool, &umfPoolDestroy);
    umf_ipc_handler_handle_t handler = nullptr;
    ASSERT_EQ(umfPoolGetIPCHandler(pool.get(), &handler), UMF_RESULT_SUCCESS);
    auto tracking_provider =
        reinterpret_cast<umf_memory_provider_handle_t>(handler);
    size_t ipc_handle_size = 0;
    ASSERT_EQ(
        umfMemoryProviderGetIPCHandleSize(tracking_provider, &ipc_handle_size),
        UMF_RESULT_SUCCESS);
    void *ptr = umfPoolMalloc(pool.get(), sizeof(allocation));
    ASSERT_EQ(ptr, allocation.data());
    auto original = tracking_ipc_get(ptr, sizeof(allocation), ipc_handle_size,
                                     tracking_provider, provider.get());
    ASSERT_EQ(original.result, UMF_RESULT_SUCCESS);

    umf_result_t free_result = UMF_RESULT_ERROR_UNKNOWN;
    std::thread freer([&] { free_result = umfPoolFree(pool.get(), ptr); });
    // The mock can reuse its fixed address once upstream Free is entered.
    bool free_entered = wait_for_tracking_ipc_state(
        state, [&] { return state.free_calls == 1; });
    void *reused_ptr = nullptr;
    tracking_ipc_get_result replacement;
    if (free_entered) {
        reused_ptr = umfPoolMalloc(pool.get(), sizeof(allocation));
        if (reused_ptr) {
            replacement = tracking_ipc_get(reused_ptr, sizeof(allocation),
                                           ipc_handle_size, tracking_provider,
                                           provider.get());
        }
    }
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        EXPECT_EQ(state.get_calls, 2u);
        EXPECT_EQ(state.put_handles,
                  std::vector<uint64_t>{original.provider_data});
        state.release_free = true;
        state.cv.notify_all();
    }
    freer.join();

    ASSERT_TRUE(free_entered);
    EXPECT_EQ(free_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(reused_ptr, ptr);
    EXPECT_EQ(replacement.result, UMF_RESULT_SUCCESS);
    EXPECT_NE(replacement.handle_id, original.handle_id);
    EXPECT_NE(replacement.provider_data, original.provider_data);

    auto cached =
        tracking_ipc_get(reused_ptr, sizeof(allocation), ipc_handle_size,
                         tracking_provider, provider.get());
    EXPECT_EQ(cached.result, UMF_RESULT_SUCCESS);
    EXPECT_EQ(cached.handle_id, replacement.handle_id);
    EXPECT_EQ(cached.provider_data, replacement.provider_data);
    EXPECT_EQ(umfPoolFree(pool.get(), reused_ptr), UMF_RESULT_SUCCESS);
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        EXPECT_EQ(state.get_calls, 2u);
        EXPECT_EQ(state.put_calls, 2u);
        EXPECT_EQ(state.free_calls, 2u);
        EXPECT_EQ(state.put_handles,
                  (std::vector<uint64_t>{original.provider_data,
                                         replacement.provider_data}));
    }
}

TEST(TrackingProviderIpcConcurrencyTest, free_waits_for_get_initialization) {
    tracking_ipc_test_state state;
    state.block_get = true;
    umf_memory_provider_handle_t raw_provider = nullptr;
    umf_memory_pool_handle_t raw_pool = nullptr;
    ASSERT_EQ(create_tracking_ipc_test_pool(&state, &raw_provider, &raw_pool),
              UMF_RESULT_SUCCESS);
    umf_test::provider_unique_handle_t provider(raw_provider,
                                                &umfMemoryProviderDestroy);
    umf_test::pool_unique_handle_t pool(raw_pool, &umfPoolDestroy);
    umf_ipc_handler_handle_t raw_tracking_provider = nullptr;
    ASSERT_EQ(umfPoolGetIPCHandler(pool.get(), &raw_tracking_provider),
              UMF_RESULT_SUCCESS);
    auto tracking_provider =
        reinterpret_cast<umf_memory_provider_handle_t>(raw_tracking_provider);
    size_t ipc_handle_size = 0;
    ASSERT_EQ(
        umfMemoryProviderGetIPCHandleSize(tracking_provider, &ipc_handle_size),
        UMF_RESULT_SUCCESS);

    void *ptr = umfPoolMalloc(pool.get(), 128);
    ASSERT_NE(ptr, nullptr);
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        state.block_size = true;
        state.size_entered = false;
        state.block_get = true;
    }
    tracking_ipc_get_result get_result;
    std::thread getter([&] {
        get_result = tracking_ipc_get(ptr, 128, ipc_handle_size,
                                      tracking_provider, provider.get());
    });
    bool size_entered =
        wait_for_tracking_ipc_state(state, [&] { return state.size_entered; });

    std::atomic<bool> free_started = false;
    umf_result_t free_result = UMF_RESULT_ERROR_UNKNOWN;
    std::thread freer([&] {
        free_started = true;
        free_result = umfPoolFree(pool.get(), ptr);
    });
    while (!free_started) {
        std::this_thread::yield();
    }
    release_tracking_ipc_size(state);
    bool get_entered =
        wait_for_tracking_ipc_state(state, [&] { return state.get_entered; });
    bool free_waiting =
        wait_for_tracking_ipc_waiters(tracking_provider, ptr, 1);
    tracking_ipc_get_result rejected_result;
    std::thread rejected_getter([&] {
        rejected_result = tracking_ipc_get(ptr, 128, ipc_handle_size,
                                           tracking_provider, provider.get());
    });
    bool rejected_get_joined =
        wait_for_tracking_ipc_waiters(tracking_provider, ptr, 2);
    size_t free_calls_while_get_blocked = 0;
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        free_calls_while_get_blocked = state.free_calls;
    }

    release_tracking_ipc_get(state);
    getter.join();
    freer.join();
    rejected_getter.join();

    ASSERT_TRUE(size_entered);
    ASSERT_TRUE(get_entered);
    ASSERT_TRUE(free_waiting);
    ASSERT_TRUE(rejected_get_joined);
    EXPECT_EQ(free_calls_while_get_blocked, 0u);
    EXPECT_EQ(get_result.result, UMF_RESULT_SUCCESS);
    EXPECT_EQ(free_result, UMF_RESULT_SUCCESS);
    EXPECT_EQ(rejected_result.result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    EXPECT_NE(get_result.handle_id, 0u);
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        EXPECT_EQ(state.get_calls, 1u);
        EXPECT_EQ(state.put_calls, 1u);
        EXPECT_EQ(state.free_calls, 1u);
    }
}
