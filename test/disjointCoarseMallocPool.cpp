/*
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <random>

#include "provider.hpp"

#include <umf/pools/pool_disjoint.h>
#include <umf/providers/provider_coarse.h>

using umf_test::KB;
using umf_test::MB;
using umf_test::test;

#define GetStats umfCoarseMemoryProviderGetStats

#define UPSTREAM_NAME "malloc"
#define BASE_NAME "coarse"
#define COARSE_NAME BASE_NAME " (" UPSTREAM_NAME ")"

umf_memory_provider_ops_t UMF_MALLOC_MEMORY_PROVIDER_OPS =
    umf::providerMakeCOps<umf_test::provider_malloc, void>();

struct CoarseWithMemoryStrategyTest
    : umf_test::test,
      ::testing::WithParamInterface<coarse_memory_provider_strategy_t> {
    void SetUp() override {
        test::SetUp();
        allocation_strategy = this->GetParam();
    }

    coarse_memory_provider_strategy_t allocation_strategy;
};

INSTANTIATE_TEST_SUITE_P(
    CoarseWithMemoryStrategyTest, CoarseWithMemoryStrategyTest,
    ::testing::Values(UMF_COARSE_MEMORY_STRATEGY_FASTEST,
                      UMF_COARSE_MEMORY_STRATEGY_FASTEST_BUT_ONE,
                      UMF_COARSE_MEMORY_STRATEGY_CHECK_ALL_SIZE));

TEST_F(test, disjointCoarseMallocPool_name_upstream) {
    umf_memory_provider_handle_t malloc_memory_provider;
    umf_result_t umf_result;

    umf_result = umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                                         &malloc_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(malloc_memory_provider, nullptr);

    const size_t init_buffer_size = 20 * MB;

    coarse_memory_provider_params_t coarse_memory_provider_params;
    // make sure there are no undefined members - prevent a UB
    memset(&coarse_memory_provider_params, 0,
           sizeof(coarse_memory_provider_params));
    coarse_memory_provider_params.upstream_memory_provider =
        malloc_memory_provider;
    coarse_memory_provider_params.immediate_init_from_upstream = true;
    coarse_memory_provider_params.init_buffer = nullptr;
    coarse_memory_provider_params.init_buffer_size = init_buffer_size;

    umf_memory_provider_handle_t coarse_memory_provider;
    umf_result = umfMemoryProviderCreate(umfCoarseMemoryProviderOps(),
                                         &coarse_memory_provider_params,
                                         &coarse_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_memory_provider, nullptr);

    ASSERT_EQ(
        strcmp(umfMemoryProviderGetName(coarse_memory_provider), COARSE_NAME),
        0);

    umfMemoryProviderDestroy(coarse_memory_provider);
    umfMemoryProviderDestroy(malloc_memory_provider);
}

TEST_F(test, disjointCoarseMallocPool_name_no_upstream) {
    umf_result_t umf_result;

    const size_t init_buffer_size = 20 * MB;

    // Preallocate some memory
    std::unique_ptr<char[]> buffer(new char[init_buffer_size]);
    void *buf = buffer.get();
    ASSERT_NE(buf, nullptr);
    memset(buf, 0, init_buffer_size);

    coarse_memory_provider_params_t coarse_memory_provider_params;
    // make sure there are no undefined members - prevent a UB
    memset(&coarse_memory_provider_params, 0,
           sizeof(coarse_memory_provider_params));
    coarse_memory_provider_params.upstream_memory_provider = nullptr;
    coarse_memory_provider_params.immediate_init_from_upstream = false;
    coarse_memory_provider_params.init_buffer = buf;
    coarse_memory_provider_params.init_buffer_size = init_buffer_size;

    umf_memory_provider_handle_t coarse_memory_provider;
    umf_result = umfMemoryProviderCreate(umfCoarseMemoryProviderOps(),
                                         &coarse_memory_provider_params,
                                         &coarse_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_memory_provider, nullptr);

    ASSERT_EQ(
        strcmp(umfMemoryProviderGetName(coarse_memory_provider), BASE_NAME), 0);

    umfMemoryProviderDestroy(coarse_memory_provider);
}

TEST_P(CoarseWithMemoryStrategyTest, disjointCoarseMallocPool_basic) {
    umf_memory_provider_handle_t malloc_memory_provider;
    umf_result_t umf_result;

    umf_result = umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                                         &malloc_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(malloc_memory_provider, nullptr);

    const size_t init_buffer_size = 20 * MB;

    coarse_memory_provider_params_t coarse_memory_provider_params;
    // make sure there are no undefined members - prevent a UB
    memset(&coarse_memory_provider_params, 0,
           sizeof(coarse_memory_provider_params));
    coarse_memory_provider_params.allocation_strategy = allocation_strategy;
    coarse_memory_provider_params.upstream_memory_provider =
        malloc_memory_provider;
    coarse_memory_provider_params.immediate_init_from_upstream = true;
    coarse_memory_provider_params.init_buffer = nullptr;
    coarse_memory_provider_params.init_buffer_size = init_buffer_size;

    umf_memory_provider_handle_t coarse_memory_provider;
    umf_result = umfMemoryProviderCreate(umfCoarseMemoryProviderOps(),
                                         &coarse_memory_provider_params,
                                         &coarse_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_memory_provider, nullptr);

    umf_disjoint_pool_params_t disjoint_memory_pool_params = {};
    disjoint_memory_pool_params.SlabMinSize = 4096;
    disjoint_memory_pool_params.MaxPoolableSize = 4096;
    disjoint_memory_pool_params.Capacity = 4;
    disjoint_memory_pool_params.MinBucketSize = 64;
    disjoint_memory_pool_params.PoolTrace = 1;

    umf_memory_pool_handle_t pool;
    umf_result = umfPoolCreate(umfDisjointPoolOps(), coarse_memory_provider,
                               &disjoint_memory_pool_params,
                               UMF_POOL_CREATE_FLAG_NONE, &pool);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(pool, nullptr);

    // test

    umf_memory_provider_handle_t prov = NULL;
    umf_result = umfPoolGetMemoryProvider(pool, &prov);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(prov, nullptr);

    // alloc 2x 2MB
    void *p1 = umfPoolMalloc(pool, 2 * MB);
    ASSERT_NE(p1, nullptr);
    ASSERT_EQ(GetStats(prov).used_size, 2 * MB);
    ASSERT_EQ(GetStats(prov).alloc_size, init_buffer_size);
    ASSERT_EQ(GetStats(prov).num_all_blocks, 2);

    void *p2 = umfPoolMalloc(pool, 2 * MB);
    ASSERT_NE(p2, nullptr);
    ASSERT_EQ(GetStats(prov).used_size, 4 * MB);
    ASSERT_EQ(GetStats(prov).alloc_size, init_buffer_size);
    ASSERT_EQ(GetStats(prov).num_all_blocks, 3);
    ASSERT_NE(p1, p2);

    // swap pointers to get p1 < p2
    if (p1 > p2) {
        std::swap(p1, p2);
    }

    // free + alloc first block
    // the block should be reused
    // currently there is no purging, so the alloc size shouldn't change
    // there should be no block merging between used and not-used blocks
    umf_result = umfPoolFree(pool, p1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(GetStats(prov).used_size, 2 * MB);
    ASSERT_EQ(GetStats(prov).alloc_size, init_buffer_size);
    ASSERT_EQ(GetStats(prov).num_all_blocks, 3);

    p1 = umfPoolMalloc(pool, 2 * MB);
    ASSERT_EQ(GetStats(prov).used_size, 4 * MB);
    ASSERT_EQ(GetStats(prov).alloc_size, init_buffer_size);
    ASSERT_EQ(GetStats(prov).num_all_blocks, 3);

    // free all allocs
    // overall alloc size shouldn't change
    // block p2 should merge with the prev free block p1
    // and the remaining init block
    umf_result = umfPoolFree(pool, p1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(GetStats(prov).num_all_blocks, 3);
    umf_result = umfPoolFree(pool, p2);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(GetStats(prov).used_size, 0 * MB);
    ASSERT_EQ(GetStats(prov).alloc_size, init_buffer_size);
    ASSERT_EQ(GetStats(prov).num_all_blocks, 1);

    // test allocations with alignment
    // TODO: what about holes?
    p1 = umfPoolAlignedMalloc(pool, 1 * MB - 4, 128);
    ASSERT_NE(p1, nullptr);
    ASSERT_EQ((uintptr_t)p1 & 127, 0);
    p2 = umfPoolAlignedMalloc(pool, 1 * MB - 4, 128);
    ASSERT_NE(p2, nullptr);
    ASSERT_EQ((uintptr_t)p1 & 127, 0);
    umf_result = umfPoolFree(pool, p1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    umf_result = umfPoolFree(pool, p2);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    // alloc whole buffer
    // after this, there should be one single block
    p1 = umfPoolMalloc(pool, init_buffer_size);
    ASSERT_EQ(GetStats(prov).used_size, init_buffer_size);
    ASSERT_EQ(GetStats(prov).alloc_size, init_buffer_size);
    ASSERT_EQ(GetStats(prov).num_all_blocks, 1);

    // free all memory
    // alloc 2 MB block - the init block should be split
    umf_result = umfPoolFree(pool, p1);
    p1 = umfPoolMalloc(pool, 2 * MB);
    ASSERT_EQ(GetStats(prov).used_size, 2 * MB);
    ASSERT_EQ(GetStats(prov).alloc_size, init_buffer_size);
    ASSERT_EQ(GetStats(prov).num_all_blocks, 2);

    // alloc additional 2 MB
    // the non-used block should be used
    p2 = umfPoolMalloc(pool, 2 * MB);
    ASSERT_EQ(GetStats(prov).used_size, 4 * MB);
    ASSERT_EQ(GetStats(prov).alloc_size, init_buffer_size);
    ASSERT_EQ(GetStats(prov).num_all_blocks, 3);
    ASSERT_NE(p1, p2);

    // make sure that p1 < p2
    if (p1 > p2) {
        std::swap(p1, p2);
    }

    // free blocks in order: p2, p1
    // block p1 should merge with the next block p2
    // swap pointers to get p1 < p2
    umfPoolFree(pool, p2);
    umfPoolFree(pool, p1);
    ASSERT_EQ(GetStats(prov).used_size, 0 * MB);
    ASSERT_EQ(GetStats(prov).alloc_size, init_buffer_size);
    ASSERT_EQ(GetStats(prov).num_all_blocks, 1);

    // alloc 10x 2 MB - this should occupy all allocated memory
    constexpr int allocs_size = 10;
    void *allocs[allocs_size] = {0};
    for (int i = 0; i < allocs_size; i++) {
        ASSERT_EQ(GetStats(prov).used_size, i * 2 * MB);
        allocs[i] = umfPoolMalloc(pool, 2 * MB);
        ASSERT_NE(allocs[i], nullptr);
    }
    ASSERT_EQ(GetStats(prov).used_size, 20 * MB);
    ASSERT_EQ(GetStats(prov).alloc_size, init_buffer_size);
    // there should be no block with the free memory
    ASSERT_EQ(GetStats(prov).num_all_blocks, allocs_size);

    // free all memory
    for (int i = 0; i < allocs_size; i++) {
        umf_result = umfPoolFree(pool, allocs[i]);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    }

    ASSERT_EQ(GetStats(prov).num_all_blocks, 1);
    ASSERT_EQ(GetStats(prov).used_size, 0 * MB);
    ASSERT_EQ(GetStats(prov).alloc_size, init_buffer_size);

    umfPoolDestroy(pool);
    umfMemoryProviderDestroy(coarse_memory_provider);
    umfMemoryProviderDestroy(malloc_memory_provider);
}

TEST_P(CoarseWithMemoryStrategyTest, disjointCoarseMallocPool_simple1) {
    umf_memory_provider_handle_t malloc_memory_provider;
    umf_result_t umf_result;

    umf_result = umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                                         &malloc_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(malloc_memory_provider, nullptr);

    const size_t init_buffer_size = 20 * MB;

    coarse_memory_provider_params_t coarse_memory_provider_params;
    // make sure there are no undefined members - prevent a UB
    memset(&coarse_memory_provider_params, 0,
           sizeof(coarse_memory_provider_params));
    coarse_memory_provider_params.allocation_strategy = allocation_strategy;
    coarse_memory_provider_params.upstream_memory_provider =
        malloc_memory_provider;
    coarse_memory_provider_params.immediate_init_from_upstream = true;
    coarse_memory_provider_params.init_buffer = NULL;
    coarse_memory_provider_params.init_buffer_size = init_buffer_size;

    umf_memory_provider_handle_t coarse_memory_provider;
    umf_result = umfMemoryProviderCreate(umfCoarseMemoryProviderOps(),
                                         &coarse_memory_provider_params,
                                         &coarse_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_memory_provider, nullptr);

    umf_disjoint_pool_params_t disjoint_memory_pool_params = {};
    disjoint_memory_pool_params.SlabMinSize = 4096;
    disjoint_memory_pool_params.MaxPoolableSize = 4096;
    disjoint_memory_pool_params.Capacity = 4;
    disjoint_memory_pool_params.MinBucketSize = 64;
    disjoint_memory_pool_params.PoolTrace = 1;

    umf_memory_pool_handle_t pool;
    umf_result = umfPoolCreate(umfDisjointPoolOps(), coarse_memory_provider,
                               &disjoint_memory_pool_params,
                               UMF_POOL_CREATE_FLAG_NONE, &pool);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(pool, nullptr);

    umf_memory_provider_handle_t prov = NULL;
    umfPoolGetMemoryProvider(pool, &prov);
    ASSERT_NE(prov, nullptr);

    // test 1

    size_t s1 = 74659 * KB;
    size_t s2 = 8206 * KB;

    size_t max_alloc_size = 0;

    const int nreps = 2;
    const int nptrs = 6;

    // s1
    for (int j = 0; j < nreps; j++) {
        void *t[nptrs] = {0};
        for (int i = 0; i < nptrs; i++) {
            t[i] = umfPoolMalloc(pool, s1);
            ASSERT_NE(t[i], nullptr);
        }

        if (max_alloc_size == 0) {
            max_alloc_size = GetStats(prov).alloc_size;
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

        // all s2 should fit into single block leaved after freeing s1
        ASSERT_LE(GetStats(prov).alloc_size, max_alloc_size);

        for (int i = 0; i < nptrs; i++) {
            umf_result = umfPoolFree(pool, t[i]);
            ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        }
    }

    umfPoolDestroy(pool);
    umfMemoryProviderDestroy(coarse_memory_provider);
    umfMemoryProviderDestroy(malloc_memory_provider);
}

TEST_P(CoarseWithMemoryStrategyTest, disjointCoarseMallocPool_simple2) {
    umf_memory_provider_handle_t malloc_memory_provider;
    umf_result_t umf_result;

    umf_result = umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                                         &malloc_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(malloc_memory_provider, nullptr);

    const size_t init_buffer_size = 20 * MB;

    coarse_memory_provider_params_t coarse_memory_provider_params;
    // make sure there are no undefined members - prevent a UB
    memset(&coarse_memory_provider_params, 0,
           sizeof(coarse_memory_provider_params));
    coarse_memory_provider_params.allocation_strategy = allocation_strategy;
    coarse_memory_provider_params.upstream_memory_provider =
        malloc_memory_provider;
    coarse_memory_provider_params.immediate_init_from_upstream = true;
    coarse_memory_provider_params.init_buffer = NULL;
    coarse_memory_provider_params.init_buffer_size = init_buffer_size;

    umf_memory_provider_handle_t coarse_memory_provider;
    umf_result = umfMemoryProviderCreate(umfCoarseMemoryProviderOps(),
                                         &coarse_memory_provider_params,
                                         &coarse_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_memory_provider, nullptr);

    umf_disjoint_pool_params_t disjoint_memory_pool_params = {};
    disjoint_memory_pool_params.SlabMinSize = 4096;
    disjoint_memory_pool_params.MaxPoolableSize = 4096;
    disjoint_memory_pool_params.Capacity = 4;
    disjoint_memory_pool_params.MinBucketSize = 64;
    disjoint_memory_pool_params.PoolTrace = 1;

    umf_memory_pool_handle_t pool;
    umf_result = umfPoolCreate(umfDisjointPoolOps(), coarse_memory_provider,
                               &disjoint_memory_pool_params,
                               UMF_POOL_CREATE_FLAG_NONE, &pool);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(pool, nullptr);

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
    umfMemoryProviderDestroy(coarse_memory_provider);
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

TEST_P(CoarseWithMemoryStrategyTest, disjointCoarseMMapPool_random) {
    umf_result_t umf_result;

    const size_t init_buffer_size = 200 * MB;

    // Preallocate some memory
    std::unique_ptr<char[]> buffer(new char[init_buffer_size]);
    void *buf = buffer.get();
    ASSERT_NE(buf, nullptr);
    memset(buf, 0, init_buffer_size);

    const unsigned char alloc_check_val = 11;

    coarse_memory_provider_params_t coarse_memory_provider_params;
    // make sure there are no undefined members - prevent a UB
    memset(&coarse_memory_provider_params, 0,
           sizeof(coarse_memory_provider_params));
    coarse_memory_provider_params.allocation_strategy = allocation_strategy;
    coarse_memory_provider_params.upstream_memory_provider = NULL;
    coarse_memory_provider_params.immediate_init_from_upstream = false;
    coarse_memory_provider_params.init_buffer = buf;
    coarse_memory_provider_params.init_buffer_size = init_buffer_size;

    umf_memory_provider_handle_t coarse_memory_provider;
    umf_result = umfMemoryProviderCreate(umfCoarseMemoryProviderOps(),
                                         &coarse_memory_provider_params,
                                         &coarse_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_memory_provider, nullptr);

    umf_disjoint_pool_params_t disjoint_memory_pool_params = {};
    disjoint_memory_pool_params.SlabMinSize = 1024;
    disjoint_memory_pool_params.MaxPoolableSize = 1024;
    disjoint_memory_pool_params.Capacity = 2;
    disjoint_memory_pool_params.MinBucketSize = 16;
    disjoint_memory_pool_params.PoolTrace = 1;

    umf_memory_pool_handle_t pool;
    umf_result = umfPoolCreate(umfDisjointPoolOps(), coarse_memory_provider,
                               &disjoint_memory_pool_params,
                               UMF_POOL_CREATE_FLAG_NONE, &pool);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(pool, nullptr);

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
                void *ptr = umfPoolMalloc(pool, size);
                ASSERT_NE(ptr, nullptr);

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
    umfMemoryProviderDestroy(coarse_memory_provider);
}

// negative tests

TEST_P(CoarseWithMemoryStrategyTest, disjointCoarseMallocPool_null_stats) {
    ASSERT_EQ(GetStats(nullptr).alloc_size, 0);
    ASSERT_EQ(GetStats(nullptr).used_size, 0);
    ASSERT_EQ(GetStats(nullptr).num_upstream_blocks, 0);
    ASSERT_EQ(GetStats(nullptr).num_all_blocks, 0);
    ASSERT_EQ(GetStats(nullptr).num_free_blocks, 0);
}

// wrong parameters: given no upstream_memory_provider
// nor init_buffer while exactly one of them must be set
TEST_P(CoarseWithMemoryStrategyTest, disjointCoarseMallocPool_wrong_params_0) {
    umf_result_t umf_result;

    coarse_memory_provider_params_t coarse_memory_provider_params;
    // make sure there are no undefined members - prevent a UB
    memset(&coarse_memory_provider_params, 0,
           sizeof(coarse_memory_provider_params));
    coarse_memory_provider_params.allocation_strategy = allocation_strategy;
    coarse_memory_provider_params.upstream_memory_provider = nullptr;
    coarse_memory_provider_params.immediate_init_from_upstream = false;
    coarse_memory_provider_params.init_buffer = nullptr;
    coarse_memory_provider_params.init_buffer_size = 0;

    umf_memory_provider_handle_t coarse_memory_provider = nullptr;
    umf_result = umfMemoryProviderCreate(umfCoarseMemoryProviderOps(),
                                         &coarse_memory_provider_params,
                                         &coarse_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(coarse_memory_provider, nullptr);
}

// wrong parameters: given both an upstream_memory_provider
// and an init_buffer while only one of them is allowed
TEST_P(CoarseWithMemoryStrategyTest, disjointCoarseMallocPool_wrong_params_1) {
    umf_memory_provider_handle_t malloc_memory_provider;
    umf_result_t umf_result;

    umf_result = umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                                         &malloc_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(malloc_memory_provider, nullptr);

    const size_t init_buffer_size = 20 * MB;

    // Preallocate some memory
    std::unique_ptr<char[]> buffer(new char[init_buffer_size]);
    void *buf = buffer.get();
    ASSERT_NE(buf, nullptr);
    memset(buf, 0, init_buffer_size);

    coarse_memory_provider_params_t coarse_memory_provider_params;
    // make sure there are no undefined members - prevent a UB
    memset(&coarse_memory_provider_params, 0,
           sizeof(coarse_memory_provider_params));
    coarse_memory_provider_params.allocation_strategy = allocation_strategy;
    coarse_memory_provider_params.upstream_memory_provider =
        malloc_memory_provider;
    coarse_memory_provider_params.immediate_init_from_upstream = true;
    coarse_memory_provider_params.init_buffer = buf;
    coarse_memory_provider_params.init_buffer_size = init_buffer_size;

    umf_memory_provider_handle_t coarse_memory_provider = nullptr;
    umf_result = umfMemoryProviderCreate(umfCoarseMemoryProviderOps(),
                                         &coarse_memory_provider_params,
                                         &coarse_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(coarse_memory_provider, nullptr);

    umfMemoryProviderDestroy(malloc_memory_provider);
}

// wrong parameters: init_buffer_size must not equal 0 when immediate_init_from_upstream is true
TEST_P(CoarseWithMemoryStrategyTest, disjointCoarseMallocPool_wrong_params_2) {
    umf_memory_provider_handle_t malloc_memory_provider;
    umf_result_t umf_result;

    umf_result = umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                                         &malloc_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(malloc_memory_provider, nullptr);

    coarse_memory_provider_params_t coarse_memory_provider_params;
    // make sure there are no undefined members - prevent a UB
    memset(&coarse_memory_provider_params, 0,
           sizeof(coarse_memory_provider_params));
    coarse_memory_provider_params.allocation_strategy = allocation_strategy;
    coarse_memory_provider_params.upstream_memory_provider =
        malloc_memory_provider;
    coarse_memory_provider_params.immediate_init_from_upstream = true;
    coarse_memory_provider_params.init_buffer = nullptr;
    coarse_memory_provider_params.init_buffer_size = 0;

    umf_memory_provider_handle_t coarse_memory_provider = nullptr;
    umf_result = umfMemoryProviderCreate(umfCoarseMemoryProviderOps(),
                                         &coarse_memory_provider_params,
                                         &coarse_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(coarse_memory_provider, nullptr);

    umfMemoryProviderDestroy(malloc_memory_provider);
}

// wrong parameters: init_buffer_size must not equal 0 when init_buffer is not NULL
TEST_P(CoarseWithMemoryStrategyTest, disjointCoarseMallocPool_wrong_params_3) {
    umf_result_t umf_result;

    const size_t init_buffer_size = 20 * MB;

    // Preallocate some memory
    std::unique_ptr<char[]> buffer(new char[init_buffer_size]);
    void *buf = buffer.get();
    ASSERT_NE(buf, nullptr);
    memset(buf, 0, init_buffer_size);

    coarse_memory_provider_params_t coarse_memory_provider_params;
    // make sure there are no undefined members - prevent a UB
    memset(&coarse_memory_provider_params, 0,
           sizeof(coarse_memory_provider_params));
    coarse_memory_provider_params.allocation_strategy = allocation_strategy;
    coarse_memory_provider_params.upstream_memory_provider = nullptr;
    coarse_memory_provider_params.immediate_init_from_upstream = false;
    coarse_memory_provider_params.init_buffer = buf;
    coarse_memory_provider_params.init_buffer_size = 0;

    umf_memory_provider_handle_t coarse_memory_provider = nullptr;
    umf_result = umfMemoryProviderCreate(umfCoarseMemoryProviderOps(),
                                         &coarse_memory_provider_params,
                                         &coarse_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(coarse_memory_provider, nullptr);
}

// wrong parameters: init_buffer_size must equal 0 when init_buffer is NULL and immediate_init_from_upstream is false
TEST_P(CoarseWithMemoryStrategyTest, disjointCoarseMallocPool_wrong_params_4) {
    umf_memory_provider_handle_t malloc_memory_provider;
    umf_result_t umf_result;

    umf_result = umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                                         &malloc_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(malloc_memory_provider, nullptr);

    coarse_memory_provider_params_t coarse_memory_provider_params;
    // make sure there are no undefined members - prevent a UB
    memset(&coarse_memory_provider_params, 0,
           sizeof(coarse_memory_provider_params));
    coarse_memory_provider_params.allocation_strategy = allocation_strategy;
    coarse_memory_provider_params.upstream_memory_provider =
        malloc_memory_provider;
    coarse_memory_provider_params.immediate_init_from_upstream = false;
    coarse_memory_provider_params.init_buffer = NULL;
    coarse_memory_provider_params.init_buffer_size = 20 * MB;

    umf_memory_provider_handle_t coarse_memory_provider = nullptr;
    umf_result = umfMemoryProviderCreate(umfCoarseMemoryProviderOps(),
                                         &coarse_memory_provider_params,
                                         &coarse_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(coarse_memory_provider, nullptr);

    umfMemoryProviderDestroy(malloc_memory_provider);
}

TEST_P(CoarseWithMemoryStrategyTest, disjointCoarseMallocPool_split_merge) {
    umf_memory_provider_handle_t malloc_memory_provider;
    umf_result_t umf_result;

    umf_result = umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                                         &malloc_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(malloc_memory_provider, nullptr);

    const size_t init_buffer_size = 20 * MB;

    coarse_memory_provider_params_t coarse_memory_provider_params;
    // make sure there are no undefined members - prevent a UB
    memset(&coarse_memory_provider_params, 0,
           sizeof(coarse_memory_provider_params));
    coarse_memory_provider_params.upstream_memory_provider =
        malloc_memory_provider;
    coarse_memory_provider_params.immediate_init_from_upstream = true;
    coarse_memory_provider_params.init_buffer = NULL;
    coarse_memory_provider_params.init_buffer_size = init_buffer_size;

    umf_memory_provider_handle_t coarse_memory_provider;
    umf_result = umfMemoryProviderCreate(umfCoarseMemoryProviderOps(),
                                         &coarse_memory_provider_params,
                                         &coarse_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_memory_provider, nullptr);

    umf_memory_provider_handle_t cp = coarse_memory_provider;
    char *ptr = nullptr;

    ASSERT_EQ(GetStats(cp).used_size, 0 * MB);
    ASSERT_EQ(GetStats(cp).alloc_size, init_buffer_size);
    ASSERT_EQ(GetStats(cp).num_all_blocks, 1);

    /* test umfMemoryProviderAllocationSplit */
    umf_result = umfMemoryProviderAlloc(cp, 2 * MB, 0, (void **)&ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);
    ASSERT_EQ(GetStats(cp).used_size, 2 * MB);
    ASSERT_EQ(GetStats(cp).alloc_size, init_buffer_size);
    ASSERT_EQ(GetStats(cp).num_all_blocks, 2);

    umf_result = umfMemoryProviderAllocationSplit(cp, ptr, 2 * MB, 1 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(GetStats(cp).used_size, 2 * MB);
    ASSERT_EQ(GetStats(cp).alloc_size, init_buffer_size);
    ASSERT_EQ(GetStats(cp).num_all_blocks, 3);

    umf_result = umfMemoryProviderFree(cp, (ptr + 1 * MB), 1 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(GetStats(cp).used_size, 1 * MB);
    ASSERT_EQ(GetStats(cp).alloc_size, init_buffer_size);
    ASSERT_EQ(GetStats(cp).num_all_blocks, 2);

    umf_result = umfMemoryProviderFree(cp, ptr, 1 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(GetStats(cp).used_size, 0);
    ASSERT_EQ(GetStats(cp).alloc_size, init_buffer_size);
    ASSERT_EQ(GetStats(cp).num_all_blocks, 1);

    /* test umfMemoryProviderAllocationMerge */
    umf_result = umfMemoryProviderAlloc(cp, 2 * MB, 0, (void **)&ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);
    ASSERT_EQ(GetStats(cp).used_size, 2 * MB);
    ASSERT_EQ(GetStats(cp).alloc_size, init_buffer_size);
    ASSERT_EQ(GetStats(cp).num_all_blocks, 2);

    umf_result = umfMemoryProviderAllocationSplit(cp, ptr, 2 * MB, 1 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(GetStats(cp).used_size, 2 * MB);
    ASSERT_EQ(GetStats(cp).alloc_size, init_buffer_size);
    ASSERT_EQ(GetStats(cp).num_all_blocks, 3);

    umf_result =
        umfMemoryProviderAllocationMerge(cp, ptr, (ptr + 1 * MB), 2 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(GetStats(cp).used_size, 2 * MB);
    ASSERT_EQ(GetStats(cp).alloc_size, init_buffer_size);
    ASSERT_EQ(GetStats(cp).num_all_blocks, 2);

    umf_result = umfMemoryProviderFree(cp, ptr, 2 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(GetStats(cp).used_size, 0);
    ASSERT_EQ(GetStats(cp).alloc_size, init_buffer_size);
    ASSERT_EQ(GetStats(cp).num_all_blocks, 1);

    umfMemoryProviderDestroy(coarse_memory_provider);
    umfMemoryProviderDestroy(malloc_memory_provider);
}

TEST_P(CoarseWithMemoryStrategyTest,
       disjointCoarseMallocPool_split_merge_negative) {
    umf_memory_provider_handle_t malloc_memory_provider;
    umf_result_t umf_result;

    umf_result = umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                                         &malloc_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(malloc_memory_provider, nullptr);

    const size_t init_buffer_size = 20 * MB;

    coarse_memory_provider_params_t coarse_memory_provider_params;
    // make sure there are no undefined members - prevent a UB
    memset(&coarse_memory_provider_params, 0,
           sizeof(coarse_memory_provider_params));
    coarse_memory_provider_params.upstream_memory_provider =
        malloc_memory_provider;
    coarse_memory_provider_params.immediate_init_from_upstream = true;
    coarse_memory_provider_params.init_buffer = NULL;
    coarse_memory_provider_params.init_buffer_size = init_buffer_size;

    umf_memory_provider_handle_t coarse_memory_provider;
    umf_result = umfMemoryProviderCreate(umfCoarseMemoryProviderOps(),
                                         &coarse_memory_provider_params,
                                         &coarse_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_memory_provider, nullptr);

    umf_memory_provider_handle_t cp = coarse_memory_provider;
    char *ptr = nullptr;

    ASSERT_EQ(GetStats(cp).used_size, 0 * MB);
    ASSERT_EQ(GetStats(cp).alloc_size, init_buffer_size);
    ASSERT_EQ(GetStats(cp).num_all_blocks, 1);

    /* test umfMemoryProviderAllocationSplit */
    umf_result = umfMemoryProviderAlloc(cp, 6 * MB, 0, (void **)&ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);
    ASSERT_EQ(GetStats(cp).used_size, 6 * MB);
    ASSERT_EQ(GetStats(cp).alloc_size, init_buffer_size);
    ASSERT_EQ(GetStats(cp).num_all_blocks, 2);

    // firstSize >= totalSize
    umf_result = umfMemoryProviderAllocationSplit(cp, ptr, 6 * MB, 6 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // firstSize == 0
    umf_result = umfMemoryProviderAllocationSplit(cp, ptr, 6 * MB, 0);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // wrong totalSize
    umf_result = umfMemoryProviderAllocationSplit(cp, ptr, 5 * MB, 1 * KB);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    /* test umfMemoryProviderAllocationMerge */
    // split (6 * MB) block into (1 * MB) + (5 * MB)
    umf_result = umfMemoryProviderAllocationSplit(cp, ptr, 6 * MB, 1 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(GetStats(cp).used_size, 6 * MB);
    ASSERT_EQ(GetStats(cp).alloc_size, init_buffer_size);
    ASSERT_EQ(GetStats(cp).num_all_blocks, 3);

    // split (5 * MB) block into (2 * MB) + (3 * MB)
    umf_result =
        umfMemoryProviderAllocationSplit(cp, (ptr + 1 * MB), 5 * MB, 2 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(GetStats(cp).used_size, 6 * MB);
    ASSERT_EQ(GetStats(cp).alloc_size, init_buffer_size);
    ASSERT_EQ(GetStats(cp).num_all_blocks, 4);

    // now we have 3 blocks: (1 * MB) + (2 * MB) + (3 * MB)

    // highPtr <= lowPtr
    umf_result =
        umfMemoryProviderAllocationMerge(cp, (ptr + 1 * MB), ptr, 2 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // highPtr - lowPtr >= totalSize
    umf_result =
        umfMemoryProviderAllocationMerge(cp, ptr, (ptr + 1 * MB), 1 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // low_block->size + high_block->size != totalSize
    umf_result =
        umfMemoryProviderAllocationMerge(cp, ptr, (ptr + 1 * MB), 5 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // not adjacent blocks
    umf_result =
        umfMemoryProviderAllocationMerge(cp, ptr, (ptr + 3 * MB), 4 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umf_result = umfMemoryProviderFree(cp, ptr, 1 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(GetStats(cp).used_size, 5 * MB);
    ASSERT_EQ(GetStats(cp).alloc_size, init_buffer_size);
    ASSERT_EQ(GetStats(cp).num_all_blocks, 4);

    umf_result = umfMemoryProviderFree(cp, (ptr + 1 * MB), 2 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(GetStats(cp).used_size, 3 * MB);
    ASSERT_EQ(GetStats(cp).alloc_size, init_buffer_size);
    ASSERT_EQ(GetStats(cp).num_all_blocks, 3);

    umf_result = umfMemoryProviderFree(cp, (ptr + 3 * MB), 3 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(GetStats(cp).used_size, 0);
    ASSERT_EQ(GetStats(cp).alloc_size, init_buffer_size);
    ASSERT_EQ(GetStats(cp).num_all_blocks, 1);

    umfMemoryProviderDestroy(coarse_memory_provider);
    umfMemoryProviderDestroy(malloc_memory_provider);
}
