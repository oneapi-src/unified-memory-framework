// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "utils.hpp"

namespace fuzz {

constexpr int MAX_PROVIDER_VECTOR_SIZE = 1024;
constexpr int MAX_POOLS_VECTOR_SIZE = 20;
constexpr int MAX_POOLS_ALLOC_SIZE = 1 * 1024;      // 1 kB
constexpr int MAX_PROVIDER_ALLOC_SIZE = 100 * 1024; // 100 kB

int umf_memory_provider_create(TestState &test_state) {
    umf_memory_provider_ops_t *provider_ops = umfOsMemoryProviderOps();
    umf_os_memory_provider_params_t params = umfOsMemoryProviderParamsDefault();
    umf_result_t res =
        umfMemoryProviderCreate(provider_ops, &params, &test_state.provider);

    if (res != UMF_RESULT_SUCCESS) {
        return -1;
    }

    return 0;
}

int umf_memory_provider_alloc(TestState &test_state) {
    void *ptr;
    size_t alloc_size;
    constexpr size_t alignment = 0;

    if (test_state.provider_memory_allocations.size() >=
        MAX_PROVIDER_VECTOR_SIZE) {
        return -1;
    }

    int ret = test_state.get_next_alloc_size(test_state, alloc_size,
                                             MAX_PROVIDER_ALLOC_SIZE);
    if (ret != 0) {
        return -1;
    }

    umf_result_t res = umfMemoryProviderAlloc(test_state.provider, alloc_size,
                                              alignment, &ptr);
    if (res != UMF_RESULT_SUCCESS) {
        return -1;
    }
    test_state.provider_memory_allocations.push_back(
        std::make_pair(ptr, alloc_size));

    return 0;
}

int umf_memory_provider_free(TestState &test_state) {
    if (test_state.provider_memory_allocations.empty()) {
        return -1;
    }

    std::pair<void *, size_t> alloc =
        test_state.provider_memory_allocations.back();
    umf_result_t res =
        umfMemoryProviderFree(test_state.provider, alloc.first, alloc.second);

    if (res != UMF_RESULT_SUCCESS) {
        return -1;
    }

    test_state.provider_memory_allocations.pop_back();
    return 0;
}

int umf_pool_create(TestState &test_state) {
    if (test_state.pools.size() > MAX_POOLS_VECTOR_SIZE) {
        return -1;
    }

    umf_memory_pool_ops_t *pool_ops = umfScalablePoolOps();
    void *pool_params = NULL;
    umf_pool_create_flags_t flags = 0;
    umf_memory_pool_handle_t pool;
    umf_result_t res =
        umfPoolCreate(pool_ops, test_state.provider, pool_params, flags, &pool);

    if (res != UMF_RESULT_SUCCESS) {
        return -1;
    }

    test_state.pools.insert(std::make_pair(pool, std::vector<void *>()));

    return 0;
}

int umf_pool_destroy(TestState &test_state) {
    if (test_state.pools.empty()) {
        return -1;
    }
    auto pool = (*test_state.pools.begin()).first;
    umfPoolDestroy(pool);
    test_state.pools.erase(pool);

    return 0;
}

int umf_pool_malloc(TestState &test_state) {
    if (test_state.pools.empty()) {
        return -1;
    }
    size_t alloc_size;
    int ret = test_state.get_next_alloc_size(test_state, alloc_size,
                                             MAX_POOLS_ALLOC_SIZE);
    if (ret != 0) {
        return -1;
    }
    auto &pool_entry = *test_state.pools.rbegin();
    void *ptr = umfPoolMalloc(pool_entry.first, alloc_size);

    pool_entry.second.push_back(ptr);

    return 0;
}

int umf_free(TestState &test_state) {
    for (auto &pool : test_state.pools) {
        if (pool.second.empty()) {
            continue;
        } else {
            umfFree(pool.second.back());
            pool.second.pop_back();
            break;
        }

        return -1;
    }
    return 0;
}

void cleanup(TestState &test_state) {
    for (auto &alloc : test_state.provider_memory_allocations) {
        umfMemoryProviderFree(test_state.provider, alloc.first, alloc.second);
    }

    for (auto &pool_entry : test_state.pools) {
        for (auto &ptr : pool_entry.second) {
            umfFree(ptr);
        }
        umfPoolDestroy(pool_entry.first);
    }

    umfMemoryProviderDestroy(test_state.provider);
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
    int next_api_call;
    auto data_provider = std::make_unique<FuzzedDataProvider>(data, size);
    TestState test_state(std::move(data_provider));
    int ret = -1;

    // clang-format off
    int (*api_wrappers[])(TestState &) = {
        umf_memory_provider_alloc,
        umf_memory_provider_free,
        umf_pool_create,
        umf_pool_destroy,
        umf_pool_malloc,
        umf_free,
    };
    // clang-format on
    umf_memory_provider_create(test_state);

    while ((next_api_call = test_state.get_next_api_call()) != -1) {
        ret = api_wrappers[next_api_call](test_state);
        if (ret) {
            cleanup(test_state);
            return -1;
        }
    }

    cleanup(test_state);
    return 0;
}
} // namespace fuzz
