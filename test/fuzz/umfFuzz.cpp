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
    std::cout << "Begin creating a provider" << std::endl;
    umf_memory_provider_ops_t *provider_ops = umfOsMemoryProviderOps();
    umf_os_memory_provider_params_t params = umfOsMemoryProviderParamsDefault();
    umf_result_t res =
        umfMemoryProviderCreate(provider_ops, &params, &test_state.provider);

    if (res != UMF_RESULT_SUCCESS) {
        std::cout << "Failed to create a memory provider: " << res << std::endl;
        return -1;
    }
    std::cout << "OS memory provider created at " << (void *)test_state.provider
              << std::endl;
    return 0;
}

int umf_memory_provider_alloc(TestState &test_state) {
    std::cout << "Begin memory_provider_alloc" << std::endl;
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
        std::cout << "Failed to get alloc size" << std::endl;
        return -1;
    }

    umf_result_t res = umfMemoryProviderAlloc(test_state.provider, alloc_size,
                                              alignment, &ptr);
    if (res != UMF_RESULT_SUCCESS) {
        std::cout << "Failed to allocate memory from the provider: " << res
                  << std::endl;
        return -1;
    }
    test_state.provider_memory_allocations.push_back(
        std::make_pair(ptr, alloc_size));
    std::cout << "Allocated memory at " << ptr << " with alloc_size "
              << alloc_size << std::endl;
    std::cout << "Size of vector with allocated memory from the provider: "
              << test_state.provider_memory_allocations.size() << std::endl;
    return 0;
}

int umf_memory_provider_free(TestState &test_state) {
    std::cout << "Begin memory_provider_free" << std::endl;
    if (test_state.provider_memory_allocations.empty()) {
        std::cout << "No memory allocated" << std::endl;
        return -1;
    }

    std::pair<void *, size_t> alloc =
        test_state.provider_memory_allocations.back();
    umf_result_t res =
        umfMemoryProviderFree(test_state.provider, alloc.first, alloc.second);

    if (res != UMF_RESULT_SUCCESS) {
        std::cout << "Failed to free memory to the provider: " << res
                  << std::endl;
        ;
        return -1;
    }

    std::cout << "Freed memory from the provider at " << alloc.first
              << " with alloc_size " << alloc.second << std::endl;
    test_state.provider_memory_allocations.pop_back();
    return 0;
}

int umf_pool_create(TestState &test_state) {
    if (test_state.pools.size() > MAX_POOLS_VECTOR_SIZE) {
        std::cout << "Max pools limit reached" << std::endl;
        return -1;
    }

    umf_memory_pool_ops_t *pool_ops = umfScalablePoolOps();
    void *pool_params = NULL;
    umf_pool_create_flags_t flags = 0;
    umf_memory_pool_handle_t pool;
    umf_result_t res =
        umfPoolCreate(pool_ops, test_state.provider, pool_params, flags, &pool);

    if (res != UMF_RESULT_SUCCESS) {
        std::cout << "Failed to create a pool: " << res << std::endl;
        return -1;
    }

    test_state.pools.insert(std::make_pair(pool, std::vector<void *>()));
    std::cout << "Scalable memory pool created at " << pool
              << " and pools available: " << test_state.pools.size()
              << std::endl;
    return 0;
}

int umf_pool_destroy(TestState &test_state) {
    std::cout << "Begin destroy pool" << std::endl;
    if (test_state.pools.empty()) {
        std::cout << "No pools created" << std::endl;
        return -1;
    }
    auto pool = (*test_state.pools.begin()).first;
    umfPoolDestroy(pool);
    test_state.pools.erase(pool);
    std::cout << "Destroyed pool at " << pool << std::endl;
    return 0;
}

int umf_pool_malloc(TestState &test_state) {
    std::cout << "Begin pool_malloc" << std::endl;
    if (test_state.pools.empty()) {
        std::cout << "No pools created" << std::endl;
        return -1;
    }
    size_t alloc_size;
    int ret = test_state.get_next_alloc_size(test_state, alloc_size,
                                             MAX_POOLS_ALLOC_SIZE);
    if (ret != 0) {
        std::cout << "Failed to get next allocation size" << std::endl;
        return -1;
    }
    auto &pool_entry = *test_state.pools.rbegin();
    void *ptr = umfPoolMalloc(pool_entry.first, alloc_size);
    if (!ptr) {
        std::cout
            << "Failed to allocate memory in the pool with handle address: "
            << pool_entry.first << std::endl;
    }

    pool_entry.second.push_back(ptr);
    std::cout << "Allocated memory at " << ptr
              << " with allocation size: " << alloc_size << std::endl;
    return 0;
}

int umf_free(TestState &test_state) {
    std::cout << "Begin releasing pool memory" << std::endl;
    for (auto &pool : test_state.pools) {
        if (pool.second.empty()) {
            continue;
        } else {
            umfFree(pool.second.back());
            pool.second.pop_back();
            std::cout << "Freed memory from the pool at: " << pool.second.back()
                      << std::endl;
            break;
        }
        std::cout << "No pool memory to free" << std::endl;
        return -1;
    }
    return 0;
}

void cleanup(TestState &test_state) {
    std::cout << "Begin cleanup state" << std::endl;
    for (auto &alloc : test_state.provider_memory_allocations) {
        umfMemoryProviderFree(test_state.provider, alloc.first, alloc.second);
    }

    for (auto &pool_entry : test_state.pools) {
        for (auto &ptr : pool_entry.second) {
            umfFree(ptr);
        }
        umfPoolDestroy(pool_entry.first);
    }
    std::cout << "Freed all allocated memory from provider and pools and "
                 "destroyed all pools"
              << std::endl;
    umfMemoryProviderDestroy(test_state.provider);
    std::cout << "Destroyed the provider" << std::endl;
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
