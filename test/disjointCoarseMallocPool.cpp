// Copyright (C) 2023 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// This file contains tests for UMF provider API

#include <random>
#include <set>
#include <string>
#include <unordered_map>

#include "../src/memory_provider_internal.h"
#include "provider.hpp"
#include "test_helpers.h"

#include <umf/pools/pool_disjoint.h>
#include <umf/providers/provider_coarse.h>
#include <umf/providers/provider_os_memory.h>

using umf_test::test;

// TODO move malloc provider somewhere

constexpr int PAGE_SIZE = 4 * 1024;

static enum umf_result_t mallocInitialize(void *params, void **pool) {
    (void)params;
    *pool = NULL;
    return UMF_RESULT_SUCCESS;
}

static void mallocFinalize(void *pool) { (void)pool; }

static enum umf_result_t mallocAlloc(void *provider, size_t size,
                                     size_t alignment, void **ptr) {
    (void)provider;
    (void)alignment;
    *ptr = calloc(1, size);
    return UMF_RESULT_SUCCESS;
}

static enum umf_result_t mallocFree(void *provider, void *ptr, size_t size) {
    (void)provider;
    (void)size;
    free(ptr);
    return UMF_RESULT_SUCCESS;
}

static void mallocGetLastError(void *provider, const char **ppMsg,
                               int32_t *pError) {
    (void)provider;
    (void)ppMsg;
    (void)pError;
    assert(0);
}

static enum umf_result_t
mallocGetRecommendedPageSize(void *provider, size_t size, size_t *pageSize) {
    (void)provider;
    (void)size;
    *pageSize = PAGE_SIZE;
    return UMF_RESULT_SUCCESS;
}

static enum umf_result_t mallocGetPageSize(void *provider, void *ptr,

                                           size_t *pageSize) {
    (void)provider;
    (void)ptr;
    *pageSize = PAGE_SIZE;
    return UMF_RESULT_SUCCESS;
}

static enum umf_result_t mallocPurgeLazy(void *provider, void *ptr,
                                         size_t size) {
    (void)provider;
    (void)ptr;
    (void)size;
    assert(0);
    return UMF_RESULT_SUCCESS;
}

static enum umf_result_t mallocPurgeForce(void *provider, void *ptr,
                                          size_t size) {
    (void)provider;
    (void)ptr;
    (void)size;
    assert(0);
    return UMF_RESULT_SUCCESS;
}

static enum umf_result_t mallocAllocSplit(void *provider, void *ptr,
                                          size_t size1, size_t size2) {
    (void)provider;
    (void)ptr;
    (void)size1;
    (void)size2;

    return UMF_RESULT_SUCCESS;
}

static enum umf_result_t mallocAllocMerge(void *provider, void *ptr1,
                                          size_t size1, void *ptr2,
                                          size_t size2) {
    (void)provider;
    (void)ptr1;
    (void)size1;
    (void)ptr2;
    (void)size2;

    return UMF_RESULT_SUCCESS;
}

static const char *mallocName(void *provider) {
    (void)provider;
    return "malloc";
}

struct umf_memory_provider_ops_t UMF_MALLOC_MEMORY_PROVIDER_OPS = {
    UMF_VERSION_CURRENT,
    mallocInitialize,
    mallocFinalize,
    mallocAlloc,
    mallocFree,
    mallocGetLastError,
    mallocGetRecommendedPageSize,
    mallocGetPageSize,
    mallocPurgeLazy,
    mallocPurgeForce,
    mallocAllocSplit,
    mallocAllocMerge,
    mallocName,
};

TEST_F(test, disjointCoarseMallocPool_basic) {
    umf_memory_provider_handle_t malloc_memory_provider;
    umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                            &malloc_memory_provider);
    ASSERT_NE(malloc_memory_provider, nullptr);

    const size_t KB = 1024;
    const size_t MB = 1024 * KB;

    const size_t init_buffer_size = 20 * MB;

    coarse_memory_provider_params_t coarse_memory_provider_params = {
        malloc_memory_provider, // upstream_memory_provider
        init_buffer_size,
        true, // immediate_init
        true, // trace
    };

    umf_memory_provider_handle_t coarse_memory_provider;
    umfMemoryProviderCreate(&UMF_COARSE_MEMORY_PROVIDER_OPS,
                            &coarse_memory_provider_params,
                            &coarse_memory_provider);
    ASSERT_NE(coarse_memory_provider, nullptr);

    umf_disjoint_pool_params_t disjoint_memory_pool_params = {};
    disjoint_memory_pool_params.SlabMinSize = 4096;
    disjoint_memory_pool_params.MaxPoolableSize = 4096;
    disjoint_memory_pool_params.Capacity = 4;
    disjoint_memory_pool_params.MinBucketSize = 64;
    disjoint_memory_pool_params.PoolTrace = 1;

    umf_memory_pool_handle_t pool;
    umfPoolCreate(&UMF_DISJOINT_POOL_OPS, coarse_memory_provider,
                  &disjoint_memory_pool_params, &pool);
    ASSERT_NE(pool, nullptr);

    // test

    umf_memory_provider_handle_t prov = NULL;
    umfPoolGetMemoryProvider(pool, &prov);
    ASSERT_NE(prov, nullptr);

    // alloc 2x 2MB
    void *p1 = umfPoolMalloc(pool, 2 * MB);

    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).used_size, 2 * MB);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).alloc_size,
              init_buffer_size);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).blocks_num, 2);

    void *p2 = umfPoolMalloc(pool, 2 * MB);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).used_size, 4 * MB);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).alloc_size,
              init_buffer_size);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).blocks_num, 3);
    ASSERT_NE(p1, p2);

    // swap pointers to get p1 < p2
    if (p1 > p2) {
        std::swap(p1, p2);
    }

    // free + alloc first block
    // the block should be reused
    // currently there is no purging, so the alloc size shouldn't change
    // there should be no block merging between used and not-used blocks
    umf_result_t res = umfPoolFree(pool, p1);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).used_size, 2 * MB);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).alloc_size,
              init_buffer_size);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).blocks_num, 3);

    p1 = umfPoolMalloc(pool, 2 * MB);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).used_size, 4 * MB);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).alloc_size,
              init_buffer_size);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).blocks_num, 3);

    // free all allocs
    // overall alloc size shouldn't change
    // block p2 should merge with the prev free block p1
    // and the remaining init block
    res = umfPoolFree(pool, p1);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).blocks_num, 3);
    res = umfPoolFree(pool, p2);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).used_size, 0 * MB);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).alloc_size,
              init_buffer_size);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).blocks_num, 1);

    // alloc whole buffer
    // after this, there should be one single block
    p1 = umfPoolMalloc(pool, init_buffer_size);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).used_size,
              init_buffer_size);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).alloc_size,
              init_buffer_size);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).blocks_num, 1);

    // free all memory
    // alloc 2 MB block - the init block should be split
    res = umfPoolFree(pool, p1);
    p1 = umfPoolMalloc(pool, 2 * MB);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).used_size, 2 * MB);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).alloc_size,
              init_buffer_size);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).blocks_num, 2);

    // alloc additional 2 MB
    // the non-used block should be used
    p2 = umfPoolMalloc(pool, 2 * MB);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).used_size, 4 * MB);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).alloc_size,
              init_buffer_size);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).blocks_num, 3);
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
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).used_size, 0 * MB);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).alloc_size,
              init_buffer_size);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).blocks_num, 1);

    // alloc 10x 2 MB - this should occupy all allocated memory
    constexpr int allocs_size = 10;
    void *allocs[allocs_size] = {0};
    for (int i = 0; i < allocs_size; i++) {
        ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).used_size, i * 2 * MB);
        allocs[i] = umfPoolMalloc(pool, 2 * MB);
        ASSERT_NE(allocs[i], nullptr);
    }
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).used_size, 20 * MB);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).alloc_size,
              init_buffer_size);
    // there should be no block with the free memory
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).blocks_num, allocs_size);

    // free all memory
    for (int i = 0; i < allocs_size; i++) {
        res = umfPoolFree(pool, allocs[i]);
        ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    }

    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).blocks_num, 1);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).used_size, 0 * MB);
    ASSERT_EQ(umfCoarseMemoryProviderGetStats(prov).alloc_size,
              init_buffer_size);

    umfPoolDestroy(pool);
    umfMemoryProviderDestroy(coarse_memory_provider);
    umfMemoryProviderDestroy(malloc_memory_provider);
}

TEST_F(test, disjointCoarseMallocPool_simple1) {
    umf_memory_provider_handle_t malloc_memory_provider;
    umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                            &malloc_memory_provider);
    ASSERT_NE(malloc_memory_provider, nullptr);

    const size_t KB = 1024;
    const size_t MB = 1024 * KB;

    const size_t init_buffer_size = 20 * MB;

    coarse_memory_provider_params_t coarse_memory_provider_params = {
        malloc_memory_provider, // upstream_memory_provider
        init_buffer_size,
        false, // immediate_init
        true,  // trace
    };

    umf_memory_provider_handle_t coarse_memory_provider;
    umfMemoryProviderCreate(&UMF_COARSE_MEMORY_PROVIDER_OPS,
                            &coarse_memory_provider_params,
                            &coarse_memory_provider);
    ASSERT_NE(coarse_memory_provider, nullptr);

    umf_disjoint_pool_params_t disjoint_memory_pool_params = {};
    disjoint_memory_pool_params.SlabMinSize = 4096;
    disjoint_memory_pool_params.MaxPoolableSize = 4096;
    disjoint_memory_pool_params.Capacity = 4;
    disjoint_memory_pool_params.MinBucketSize = 64;
    disjoint_memory_pool_params.PoolTrace = 1;

    umf_memory_pool_handle_t pool;
    umfPoolCreate(&UMF_DISJOINT_POOL_OPS, coarse_memory_provider,
                  &disjoint_memory_pool_params, &pool);
    ASSERT_NE(pool, nullptr);

    umf_memory_provider_handle_t prov = NULL;
    umfPoolGetMemoryProvider(pool, &prov);
    ASSERT_NE(prov, nullptr);

    // test 1

    size_t s1 = 74659 * KB;
    size_t s2 = 8206 * KB;

    size_t max_alloc_size = 0;

    // s1
    for (int j = 0; j < 2; j++) {
        void *t[6] = {0};
        for (int i = 0; i < 6; i++) {
            t[i] = umfPoolMalloc(pool, s1);
            ASSERT_NE(t[i], nullptr);
        }

        if (max_alloc_size == 0) {
            max_alloc_size = umfCoarseMemoryProviderGetStats(prov).alloc_size;
        }

        for (int i = 0; i < 6; i++) {
            umf_result_t res = umfPoolFree(pool, t[i]);
            ASSERT_EQ(res, UMF_RESULT_SUCCESS);
        }
    }

    // s2
    for (int j = 0; j < 2; j++) {
        void *t[6] = {0};
        for (int i = 0; i < 6; i++) {
            t[i] = umfPoolMalloc(pool, s2);
            ASSERT_NE(t[i], nullptr);
        }

        // all s2 should fit into single block leaved after freeing s1
        ASSERT_LE(umfCoarseMemoryProviderGetStats(prov).alloc_size,
                  max_alloc_size);

        for (int i = 0; i < 6; i++) {
            umf_result_t res = umfPoolFree(pool, t[i]);
            ASSERT_EQ(res, UMF_RESULT_SUCCESS);
        }
    }

    umfPoolDestroy(pool);
    umfMemoryProviderDestroy(coarse_memory_provider);
    umfMemoryProviderDestroy(malloc_memory_provider);
}

TEST_F(test, disjointCoarseMallocPool_simple2) {

    umf_memory_provider_handle_t malloc_memory_provider;
    umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                            &malloc_memory_provider);
    ASSERT_NE(malloc_memory_provider, nullptr);

    const size_t KB = 1024;
    const size_t MB = 1024 * KB;

    const size_t init_buffer_size = 20 * MB;

    coarse_memory_provider_params_t coarse_memory_provider_params = {
        malloc_memory_provider, // upstream_memory_provider
        init_buffer_size,
        false, // immediate_init
        true,  // trace
    };

    umf_memory_provider_handle_t coarse_memory_provider;
    umfMemoryProviderCreate(&UMF_COARSE_MEMORY_PROVIDER_OPS,
                            &coarse_memory_provider_params,
                            &coarse_memory_provider);
    ASSERT_NE(coarse_memory_provider, nullptr);

    umf_disjoint_pool_params_t disjoint_memory_pool_params = {};
    disjoint_memory_pool_params.SlabMinSize = 4096;
    disjoint_memory_pool_params.MaxPoolableSize = 4096;
    disjoint_memory_pool_params.Capacity = 4;
    disjoint_memory_pool_params.MinBucketSize = 64;
    disjoint_memory_pool_params.PoolTrace = 1;

    umf_memory_pool_handle_t pool;
    umfPoolCreate(&UMF_DISJOINT_POOL_OPS, coarse_memory_provider,
                  &disjoint_memory_pool_params, &pool);
    ASSERT_NE(pool, nullptr);

    // test
    double sizes[] = {2, 4, 0.5, 1, 8, 0.25};
    for (int i = 0; i < 6; i++) {
        size_t s = (size_t)(sizes[i] * MB);
        void *t[8] = {0};
        for (int j = 0; j < 8; j++) {
            t[j] = umfPoolMalloc(pool, s);
            ASSERT_NE(t[j], nullptr);
        }

        for (int j = 0; j < 8; j++) {
            umf_result_t res = umfPoolFree(pool, t[j]);
            ASSERT_EQ(res, UMF_RESULT_SUCCESS);
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

TEST_F(test, disjointCoarseMallocPool_random) {

    umf_memory_provider_handle_t malloc_memory_provider;
    umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                            &malloc_memory_provider);
    ASSERT_NE(malloc_memory_provider, nullptr);

    const size_t KB = 1024;
    const size_t MB = 1024 * KB;

    const size_t init_buffer_size = 20 * MB;

    const unsigned char alloc_check_val = 11;

    coarse_memory_provider_params_t coarse_memory_provider_params = {
        malloc_memory_provider, // upstream_memory_provider
        init_buffer_size,
        false, // immediate_init
        true,  // trace
    };

    umf_memory_provider_handle_t coarse_memory_provider;
    umfMemoryProviderCreate(&UMF_COARSE_MEMORY_PROVIDER_OPS,
                            &coarse_memory_provider_params,
                            &coarse_memory_provider);
    ASSERT_NE(coarse_memory_provider, nullptr);

    umf_disjoint_pool_params_t disjoint_memory_pool_params = {};
    disjoint_memory_pool_params.SlabMinSize = 1024;
    disjoint_memory_pool_params.MaxPoolableSize = 1024;
    disjoint_memory_pool_params.Capacity = 2;
    disjoint_memory_pool_params.MinBucketSize = 16;
    disjoint_memory_pool_params.PoolTrace = 1;

    umf_memory_pool_handle_t pool;
    umfPoolCreate(&UMF_DISJOINT_POOL_OPS, coarse_memory_provider,
                  &disjoint_memory_pool_params, &pool);
    ASSERT_NE(pool, nullptr);

    // set constant seed so each test run will have the same scenario
    uint32_t seed = 1234;
    std::mt19937 mt(seed);

    // different sizes to alloc
    std::vector<size_t> sizes = {
        15,       49,       588,       1025,     2 * KB,  5 * KB,
        160 * KB, 511 * KB, 1000 * KB, MB,       3 * MB,  7 * MB,
        19 * MB,  26 * MB,  69 * MB,   109 * MB, 111 * MB};
    std::uniform_int_distribution<int> sizes_dist(0, (int)(sizes.size() - 1));

    // each alloc would be done few times
    std::vector<size_t> counts = {1, 3, 4, 8, 9, 11};
    std::uniform_int_distribution<int> counts_dist(0, (int)(counts.size() - 1));

    // action to take will be random
    // alloc = <0, .5), free = <.5, 1)
    std::uniform_real_distribution<float> actions_dist(0, 1);

    std::set<alloc_ptr_size> allocs;
    for (size_t i = 0; i < 100; i++) {
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

                allocs.erase((*it));
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
    umfMemoryProviderDestroy(malloc_memory_provider);
}
