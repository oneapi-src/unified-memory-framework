/*
 * Copyright (C) 2023-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <random>

#include <umf/pools/pool_disjoint.h>
#include <umf/providers/provider_file_memory.h>

#include "coarse.h"
#include "provider.hpp"

using umf_test::KB;
using umf_test::MB;
using umf_test::test;

#define FILE_PATH ((char *)"tmp_file")

umf_memory_provider_ops_t UMF_MALLOC_MEMORY_PROVIDER_OPS =
    umf::providerMakeCOps<umf_test::provider_ba_global, void>();

struct FileWithMemoryStrategyTest
    : umf_test::test,
      ::testing::WithParamInterface<coarse_strategy_t> {
    void SetUp() override {
        test::SetUp();
        allocation_strategy = this->GetParam();
    }

    coarse_strategy_t allocation_strategy;
};

INSTANTIATE_TEST_SUITE_P(
    FileWithMemoryStrategyTest, FileWithMemoryStrategyTest,
    ::testing::Values(UMF_COARSE_MEMORY_STRATEGY_FASTEST,
                      UMF_COARSE_MEMORY_STRATEGY_FASTEST_BUT_ONE,
                      UMF_COARSE_MEMORY_STRATEGY_CHECK_ALL_SIZE));

TEST_P(FileWithMemoryStrategyTest, disjointFileMallocPool_simple1) {
    umf_memory_provider_handle_t malloc_memory_provider = nullptr;
    umf_result_t umf_result;

    umf_result = umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS,
                                         nullptr, &malloc_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(malloc_memory_provider, nullptr);

    umf_file_memory_provider_params_handle_t file_params = nullptr;
    umf_result = umfFileMemoryProviderParamsCreate(&file_params, FILE_PATH);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(file_params, nullptr);

    umf_memory_provider_handle_t file_memory_provider;
    umf_result = umfMemoryProviderCreate(umfFileMemoryProviderOps(),
                                         file_params, &file_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(file_memory_provider, nullptr);

    umf_result = umfFileMemoryProviderParamsDestroy(file_params);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_disjoint_pool_params_handle_t disjoint_pool_params = nullptr;
    umf_result = umfDisjointPoolParamsCreate(&disjoint_pool_params);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(disjoint_pool_params, nullptr);
    umf_result =
        umfDisjointPoolParamsSetSlabMinSize(disjoint_pool_params, 4096);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    umf_result =
        umfDisjointPoolParamsSetMaxPoolableSize(disjoint_pool_params, 4096);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    umf_result = umfDisjointPoolParamsSetCapacity(disjoint_pool_params, 4);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    umf_result =
        umfDisjointPoolParamsSetMinBucketSize(disjoint_pool_params, 64);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    umf_result = umfDisjointPoolParamsSetTrace(disjoint_pool_params, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_memory_pool_handle_t pool;
    umf_result =
        umfPoolCreate(umfDisjointPoolOps(), file_memory_provider,
                      disjoint_pool_params, UMF_POOL_CREATE_FLAG_NONE, &pool);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(pool, nullptr);

    umf_result = umfDisjointPoolParamsDestroy(disjoint_pool_params);

    umf_memory_provider_handle_t prov = nullptr;
    umfPoolGetMemoryProvider(pool, &prov);
    ASSERT_NE(prov, nullptr);

    // test 1

    size_t s1 = 74659 * KB;
    size_t s2 = 8206 * KB;

    const int nreps = 2;
    const int nptrs = 6;

    // s1
    for (int j = 0; j < nreps; j++) {
        void *t[nptrs] = {0};
        for (int i = 0; i < nptrs; i++) {
            t[i] = umfPoolMalloc(pool, s1);
            ASSERT_NE(t[i], nullptr);
        }

        for (int i = 0; i < nptrs; i++) {
            umf_result = umfPoolFree(pool, t[i]);
            ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        }
    }

    // s2
    for (int j = 0; j < nreps; j++) {
        void *t[nptrs] = {0};
        for (int i = 0; i < nptrs; i++) {
            t[i] = umfPoolMalloc(pool, s2);
            ASSERT_NE(t[i], nullptr);
        }

        for (int i = 0; i < nptrs; i++) {
            umf_result = umfPoolFree(pool, t[i]);
            ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        }
    }

    umfPoolDestroy(pool);
    umfMemoryProviderDestroy(file_memory_provider);
    umfMemoryProviderDestroy(malloc_memory_provider);
}

TEST_P(FileWithMemoryStrategyTest, disjointFileMallocPool_simple2) {
    umf_memory_provider_handle_t malloc_memory_provider = nullptr;
    umf_result_t umf_result;

    umf_result = umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS,
                                         nullptr, &malloc_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(malloc_memory_provider, nullptr);

    umf_file_memory_provider_params_handle_t file_params = nullptr;
    umf_result = umfFileMemoryProviderParamsCreate(&file_params, FILE_PATH);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(file_params, nullptr);

    umf_memory_provider_handle_t file_memory_provider;
    umf_result = umfMemoryProviderCreate(umfFileMemoryProviderOps(),
                                         file_params, &file_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(file_memory_provider, nullptr);

    umf_result = umfFileMemoryProviderParamsDestroy(file_params);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_disjoint_pool_params_handle_t disjoint_pool_params = nullptr;
    umf_result = umfDisjointPoolParamsCreate(&disjoint_pool_params);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(disjoint_pool_params, nullptr);
    umf_result =
        umfDisjointPoolParamsSetSlabMinSize(disjoint_pool_params, 4096);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    umf_result =
        umfDisjointPoolParamsSetMaxPoolableSize(disjoint_pool_params, 4096);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    umf_result = umfDisjointPoolParamsSetCapacity(disjoint_pool_params, 4);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    umf_result =
        umfDisjointPoolParamsSetMinBucketSize(disjoint_pool_params, 64);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    umf_result = umfDisjointPoolParamsSetTrace(disjoint_pool_params, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_memory_pool_handle_t pool;
    umf_result =
        umfPoolCreate(umfDisjointPoolOps(), file_memory_provider,
                      disjoint_pool_params, UMF_POOL_CREATE_FLAG_NONE, &pool);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(pool, nullptr);

    umf_result = umfDisjointPoolParamsDestroy(disjoint_pool_params);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    // test
    double sizes[] = {2, 4, 0.5, 1, 8, 0.25};
    size_t alignment[] = {0, 4, 0, 16, 32, 128};
    for (int i = 0; i < 6; i++) {
        size_t s = (size_t)(sizes[i] * MB);
        void *t[8] = {0};
        for (int j = 0; j < 8; j++) {
            t[j] = umfPoolAlignedMalloc(pool, s, alignment[i]);
            ASSERT_NE(t[j], nullptr);
        }

        for (int j = 0; j < 8; j++) {
            umf_result = umfPoolFree(pool, t[j]);
            ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        }
    }

    umfPoolDestroy(pool);
    umfMemoryProviderDestroy(file_memory_provider);
    umfMemoryProviderDestroy(malloc_memory_provider);
}

struct alloc_ptr_size {
    void *ptr;
    size_t size;

    bool operator<(const alloc_ptr_size &other) const {
        if (ptr == other.ptr) {
            return size < other.size;
        }
        return ptr < other.ptr;
    }
};

TEST_P(FileWithMemoryStrategyTest, disjointFileMMapPool_random) {
    umf_result_t umf_result;

    const size_t init_buffer_size = 200 * MB;

    // preallocate some memory and initialize the vector with zeros
    std::vector<char> buffer(init_buffer_size, 0);
    void *buf = (void *)buffer.data();
    ASSERT_NE(buf, nullptr);

    const unsigned char alloc_check_val = 11;

    umf_file_memory_provider_params_handle_t file_params = nullptr;
    umf_result = umfFileMemoryProviderParamsCreate(&file_params, FILE_PATH);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(file_params, nullptr);

    umf_memory_provider_handle_t file_memory_provider;
    umf_result = umfMemoryProviderCreate(umfFileMemoryProviderOps(),
                                         file_params, &file_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(file_memory_provider, nullptr);

    umf_result = umfFileMemoryProviderParamsDestroy(file_params);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_disjoint_pool_params_handle_t disjoint_pool_params = nullptr;
    umf_result = umfDisjointPoolParamsCreate(&disjoint_pool_params);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(disjoint_pool_params, nullptr);
    umf_result =
        umfDisjointPoolParamsSetSlabMinSize(disjoint_pool_params, 1024);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    umf_result =
        umfDisjointPoolParamsSetMaxPoolableSize(disjoint_pool_params, 1024);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    umf_result = umfDisjointPoolParamsSetCapacity(disjoint_pool_params, 2);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    umf_result =
        umfDisjointPoolParamsSetMinBucketSize(disjoint_pool_params, 16);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    umf_result = umfDisjointPoolParamsSetTrace(disjoint_pool_params, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_memory_pool_handle_t pool;
    umf_result =
        umfPoolCreate(umfDisjointPoolOps(), file_memory_provider,
                      disjoint_pool_params, UMF_POOL_CREATE_FLAG_NONE, &pool);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(pool, nullptr);

    umf_result = umfDisjointPoolParamsDestroy(disjoint_pool_params);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    // set constant seed so each test run will have the same scenario
    uint32_t seed = 1234;
    std::mt19937 mt(seed);

    // different sizes to alloc
    std::vector<size_t> sizes = {15,        49,     588,      1025,
                                 2 * KB,    5 * KB, 160 * KB, 511 * KB,
                                 1000 * KB, MB,     3 * MB,   7 * MB};
    std::uniform_int_distribution<int> sizes_dist(0, (int)(sizes.size() - 1));

    // each alloc would be done few times
    std::vector<size_t> counts = {1, 3, 4, 8, 9, 11};
    std::uniform_int_distribution<int> counts_dist(0, (int)(counts.size() - 1));

    // action to take will be random
    // alloc = <0, .5), free = <.5, 1)
    std::uniform_real_distribution<float> actions_dist(0, 1);

    std::set<alloc_ptr_size> allocs;
    const int nreps = 100;

    for (size_t i = 0; i < nreps; i++) {
        size_t count = counts[counts_dist(mt)];
        float action = actions_dist(mt);

        if (action < 0.5) {
            size_t size = sizes[sizes_dist(mt)];
            std::cout << "size: " << size << " count: " << count
                      << " action: alloc" << std::endl;

            // alloc
            for (size_t j = 0; j < count; j++) {
                void *ptr = umfPoolCalloc(pool, 1, size);
                if (ptr == nullptr) {
                    break;
                }

                // check if first and last bytes are empty and fill them with control data
                ASSERT_EQ(((unsigned char *)ptr)[0], 0);
                ASSERT_EQ(((unsigned char *)ptr)[size - 1], 0);
                ((unsigned char *)ptr)[0] = alloc_check_val;
                ((unsigned char *)ptr)[size - 1] = alloc_check_val;

                allocs.insert({ptr, size});
            }
        } else {
            std::cout << "count: " << count << " action: free" << std::endl;

            // free random allocs
            for (size_t j = 0; j < count; j++) {
                if (allocs.size() == 0) {
                    continue;
                }

                std::uniform_int_distribution<int> free_dist(
                    0, (int)(allocs.size() - 1));
                size_t free_id = free_dist(mt);
                auto it = allocs.begin();
                std::advance(it, free_id);
                auto [ptr, size] = (*it);
                ASSERT_NE(ptr, nullptr);

                // check if control bytes are set and clean them

                ASSERT_EQ(((unsigned char *)ptr)[0], alloc_check_val);
                ASSERT_EQ(((unsigned char *)ptr)[size - 1], alloc_check_val);
                ((unsigned char *)ptr)[0] = 0;
                ((unsigned char *)ptr)[size - 1] = 0;

                umf_result_t ret = umfPoolFree(pool, ptr);
                ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

                allocs.erase(it);
            }
        }
    }

    std::cout << "cleanup" << std::endl;

    while (allocs.size()) {
        umf_result_t ret = umfPoolFree(pool, (*allocs.begin()).ptr);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        allocs.erase(allocs.begin());
    }

    umfPoolDestroy(pool);
    umfMemoryProviderDestroy(file_memory_provider);
}
