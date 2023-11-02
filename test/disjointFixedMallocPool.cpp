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

#include <pool/pool_disjoint.h>
#include <provider/provider_fixed.h>

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
    *ptr = malloc(size);
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
    mallocName,
};

TEST_F(test, disjointFixedMallocPool_basic) {
    umf_memory_provider_handle_t malloc_memory_provider;
    umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                            &malloc_memory_provider);
    ASSERT_NE(malloc_memory_provider, nullptr);

    const size_t KB = 1024;
    const size_t MB = 1024 * KB;

    const size_t init_buffer_size = 20 * MB;

    fixed_memory_provider_params_t fixed_memory_provider_params = {
        malloc_memory_provider, // upstream_memory_provider
        init_buffer_size,
        true, // immediate_init
        true, // trace
    };

    umf_memory_provider_handle_t fixed_memory_provider;
    umfMemoryProviderCreate(&UMF_FIXED_MEMORY_PROVIDER_OPS,
                            &fixed_memory_provider_params,
                            &fixed_memory_provider);
    ASSERT_NE(fixed_memory_provider, nullptr);

    umf_disjoint_pool_params disjoint_memory_pool_params;
    disjoint_memory_pool_params.SlabMinSize = 4096;
    disjoint_memory_pool_params.MaxPoolableSize = 4096;
    disjoint_memory_pool_params.Capacity = 4;
    disjoint_memory_pool_params.MinBucketSize = 64;

    umf_memory_pool_handle_t pool;
    umfPoolCreate(&UMF_DISJOINT_POOL_OPS, fixed_memory_provider,
                  &disjoint_memory_pool_params, &pool);
    ASSERT_NE(pool, nullptr);

    // test

    umf_memory_provider_handle_t prov = NULL;
    umfPoolGetMemoryProvider(pool, &prov);
    ASSERT_NE(prov, nullptr);
    void *pp = umfMemoryProviderGetPriv(prov);
    ASSERT_NE(pp, nullptr);

    // alloc 2x 2MB
    void *p1 = umfPoolMalloc(pool, 2 * MB);

    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).used_size, 2 * MB);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).alloc_size, init_buffer_size);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).blocks_num, 2);

    void *p2 = umfPoolMalloc(pool, 2 * MB);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).used_size, 4 * MB);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).alloc_size, init_buffer_size);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).blocks_num, 3);
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
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).used_size, 2 * MB);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).alloc_size, init_buffer_size);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).blocks_num, 3);

    p1 = umfPoolMalloc(pool, 2 * MB);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).used_size, 4 * MB);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).alloc_size, init_buffer_size);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).blocks_num, 3);

    // free all allocs
    // overall alloc size shouldn't change
    // block p2 should merge with the prev free block p1
    // and the remaining init block
    res = umfPoolFree(pool, p1);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).blocks_num, 3);
    res = umfPoolFree(pool, p2);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).used_size, 0 * MB);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).alloc_size, init_buffer_size);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).blocks_num, 1);

    // alloc whole buffer
    // after this, there should be one single block
    p1 = umfPoolMalloc(pool, init_buffer_size);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).used_size, init_buffer_size);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).alloc_size, init_buffer_size);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).blocks_num, 1);

    // free all memory
    // alloc 2 MB block - the init block should be splitted
    res = umfPoolFree(pool, p1);
    p1 = umfPoolMalloc(pool, 2 * MB);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).used_size, 2 * MB);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).alloc_size, init_buffer_size);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).blocks_num, 2);

    // alloc additional 2 MB
    // the non-used block should be used
    p2 = umfPoolMalloc(pool, 2 * MB);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).used_size, 4 * MB);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).alloc_size, init_buffer_size);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).blocks_num, 3);
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
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).used_size, 0 * MB);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).alloc_size, init_buffer_size);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).blocks_num, 1);

    // alloc 10x 2 MB - this should occupy all allocated memory
    constexpr int allocs_size = 10;
    void *allocs[allocs_size] = {0};
    for (int i = 0; i < allocs_size; i++) {
        ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).used_size, i * 2 * MB);
        allocs[i] = umfPoolMalloc(pool, 2 * MB);
        ASSERT_NE(allocs[i], nullptr);
    }
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).used_size, 20 * MB);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).alloc_size, init_buffer_size);
    // there should be no block with the free memory
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).blocks_num, allocs_size);

    // free all memory
    for (int i = 0; i < allocs_size; i++) {
        res = umfPoolFree(pool, allocs[i]);
        ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    }

    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).blocks_num, 1);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).used_size, 0 * MB);
    ASSERT_EQ(umfFixedMemoryProviderGetStats(pp).alloc_size, init_buffer_size);

    umfPoolDestroy(pool);
    umfMemoryProviderDestroy(fixed_memory_provider);
    umfMemoryProviderDestroy(malloc_memory_provider);
}

TEST_F(test, disjointFixedMallocPool_simple1) {
    umf_memory_provider_handle_t malloc_memory_provider;
    umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                            &malloc_memory_provider);
    ASSERT_NE(malloc_memory_provider, nullptr);

    const size_t KB = 1024;
    const size_t MB = 1024 * KB;

    const size_t init_buffer_size = 20 * MB;

    fixed_memory_provider_params_t fixed_memory_provider_params = {
        malloc_memory_provider, // upstream_memory_provider
        init_buffer_size,
        false, // immediate_init
        true,  // trace
    };

    umf_memory_provider_handle_t fixed_memory_provider;
    umfMemoryProviderCreate(&UMF_FIXED_MEMORY_PROVIDER_OPS,
                            &fixed_memory_provider_params,
                            &fixed_memory_provider);
    ASSERT_NE(fixed_memory_provider, nullptr);

    umf_disjoint_pool_params disjoint_memory_pool_params;
    disjoint_memory_pool_params.SlabMinSize = 4096;
    disjoint_memory_pool_params.MaxPoolableSize = 4096;
    disjoint_memory_pool_params.Capacity = 4;
    disjoint_memory_pool_params.MinBucketSize = 64;

    umf_memory_pool_handle_t pool;
    umfPoolCreate(&UMF_DISJOINT_POOL_OPS, fixed_memory_provider,
                  &disjoint_memory_pool_params, &pool);
    ASSERT_NE(pool, nullptr);

    umf_memory_provider_handle_t prov = NULL;
    umfPoolGetMemoryProvider(pool, &prov);
    ASSERT_NE(prov, nullptr);
    void *pp = umfMemoryProviderGetPriv(prov);
    ASSERT_NE(pp, nullptr);

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
            max_alloc_size = umfFixedMemoryProviderGetStats(pp).alloc_size;
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
        ASSERT_LE(umfFixedMemoryProviderGetStats(pp).alloc_size,
                  max_alloc_size);

        for (int i = 0; i < 6; i++) {
            umf_result_t res = umfPoolFree(pool, t[i]);
            ASSERT_EQ(res, UMF_RESULT_SUCCESS);
        }
    }

    umfPoolDestroy(pool);
    umfMemoryProviderDestroy(fixed_memory_provider);
    umfMemoryProviderDestroy(malloc_memory_provider);
}

TEST_F(test, disjointFixedMallocPool_simple2) {

    umf_memory_provider_handle_t malloc_memory_provider;
    umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                            &malloc_memory_provider);
    ASSERT_NE(malloc_memory_provider, nullptr);

    const size_t KB = 1024;
    const size_t MB = 1024 * KB;

    const size_t init_buffer_size = 20 * MB;

    fixed_memory_provider_params_t fixed_memory_provider_params = {
        malloc_memory_provider, // upstream_memory_provider
        init_buffer_size,
        false, // immediate_init
        true,  // trace
    };

    umf_memory_provider_handle_t fixed_memory_provider;
    umfMemoryProviderCreate(&UMF_FIXED_MEMORY_PROVIDER_OPS,
                            &fixed_memory_provider_params,
                            &fixed_memory_provider);
    ASSERT_NE(fixed_memory_provider, nullptr);

    umf_disjoint_pool_params disjoint_memory_pool_params;
    disjoint_memory_pool_params.SlabMinSize = 4096;
    disjoint_memory_pool_params.MaxPoolableSize = 4096;
    disjoint_memory_pool_params.Capacity = 4;
    disjoint_memory_pool_params.MinBucketSize = 64;

    umf_memory_pool_handle_t pool;
    umfPoolCreate(&UMF_DISJOINT_POOL_OPS, fixed_memory_provider,
                  &disjoint_memory_pool_params, &pool);
    ASSERT_NE(pool, nullptr);

    // test
    double sizes[] = {2, 4, 0.5, 1, 8, 0.25};
    for (int i = 0; i < 6; i++) {
        size_t s = sizes[i] * MB;
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
    umfMemoryProviderDestroy(fixed_memory_provider);
    umfMemoryProviderDestroy(malloc_memory_provider);
}

TEST_F(test, disjointFixedMallocPool_random) {

    umf_memory_provider_handle_t malloc_memory_provider;
    umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                            &malloc_memory_provider);
    ASSERT_NE(malloc_memory_provider, nullptr);

    const size_t KB = 1024;
    const size_t MB = 1024 * KB;

    const size_t init_buffer_size = 20 * MB;

    fixed_memory_provider_params_t fixed_memory_provider_params = {
        malloc_memory_provider, // upstream_memory_provider
        init_buffer_size,
        false, // immediate_init
        true,  // trace
    };

    umf_memory_provider_handle_t fixed_memory_provider;
    umfMemoryProviderCreate(&UMF_FIXED_MEMORY_PROVIDER_OPS,
                            &fixed_memory_provider_params,
                            &fixed_memory_provider);
    ASSERT_NE(fixed_memory_provider, nullptr);

    umf_disjoint_pool_params disjoint_memory_pool_params;
    disjoint_memory_pool_params.SlabMinSize = 4096;
    disjoint_memory_pool_params.MaxPoolableSize = 4096;
    disjoint_memory_pool_params.Capacity = 4;
    disjoint_memory_pool_params.MinBucketSize = 64;

    umf_memory_pool_handle_t pool;
    umfPoolCreate(&UMF_DISJOINT_POOL_OPS, fixed_memory_provider,
                  &disjoint_memory_pool_params, &pool);
    ASSERT_NE(pool, nullptr);

    // set constant seed so each test run will have the same scenario
    size_t seed = 1234;
    std::mt19937 mt(seed);

    // different sizes to alloc
    std::vector<size_t> sizes = {
        15,       49,       588,       1025,     2 * KB,  5 * KB,
        160 * KB, 511 * KB, 1000 * KB, MB,       3 * MB,  7 * MB,
        19 * MB,  26 * MB,  99 * MB,   199 * MB, 211 * MB};
    std::uniform_int_distribution<int> sizes_dist(0, sizes.size() - 1);

    // each alloc would be done few times
    std::vector<size_t> counts = {1, 3, 4, 8, 12, 21};
    std::uniform_int_distribution<int> counts_dist(0, counts.size() - 1);

    // action to take will be random
    // alloc = <0, .5), free = <.5, 1)
    std::uniform_real_distribution<float> actions_dist(0, 1);

    std::set<void *> allocs;
    for (size_t i = 0; i < 10000; i++) {
        size_t size = sizes[sizes_dist(mt)];
        size_t count = counts[counts_dist(mt)];
        float action = actions_dist(mt);

        std::cout << "size: " << size << " count: " << count
                  << " action: " << ((action < 0.5) ? "alloc" : "free")
                  << std::endl;

        if (action < 0.5) {
            // alloc
            for (size_t j = 0; j < count; j++) {
                void *ptr = umfPoolMalloc(pool, size);
                ASSERT_NE(ptr, nullptr);

                allocs.insert(ptr);
            }
        } else {
            // free random allocs
            for (size_t j = 0; j < count; j++) {
                if (allocs.size() == 0) {
                    continue;
                }

                std::uniform_int_distribution<int> free_dist(0,
                                                             allocs.size() - 1);
                size_t free_id = free_dist(mt);
                auto it = allocs.begin();
                std::advance(it, free_id);
                void *ptr = (*it);
                ASSERT_NE(ptr, nullptr);

                umf_result_t ret = umfPoolFree(pool, ptr);
                ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

                allocs.erase(ptr);
            }
        }
    }

    std::cout << "cleanup" << std::endl;

    while (allocs.size()) {
        umf_result_t ret = umfPoolFree(pool, *allocs.begin());
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        allocs.erase(allocs.begin());
    }

    umfPoolDestroy(pool);
    umfMemoryProviderDestroy(fixed_memory_provider);
    umfMemoryProviderDestroy(malloc_memory_provider);
}
