/*
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <random>

#include "provider.hpp"

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

TEST_F(test, coarseProvider_name_upstream) {
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
    coarse_memory_provider_params.destroy_upstream_memory_provider = true;
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
    // malloc_memory_provider has already been destroyed
    // by umfMemoryProviderDestroy(coarse_memory_provider), because:
    // coarse_memory_provider_params.destroy_upstream_memory_provider = true;
}

TEST_F(test, coarseProvider_name_no_upstream) {
    umf_result_t umf_result;

    const size_t init_buffer_size = 20 * MB;

    // preallocate some memory and initialize the vector with zeros
    std::vector<char> buffer(init_buffer_size, 0);
    void *buf = (void *)buffer.data();
    ASSERT_NE(buf, nullptr);

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

// negative tests

TEST_P(CoarseWithMemoryStrategyTest, coarseProvider_null_stats) {
    ASSERT_EQ(GetStats(nullptr).alloc_size, 0);
    ASSERT_EQ(GetStats(nullptr).used_size, 0);
    ASSERT_EQ(GetStats(nullptr).num_upstream_blocks, 0);
    ASSERT_EQ(GetStats(nullptr).num_all_blocks, 0);
    ASSERT_EQ(GetStats(nullptr).num_free_blocks, 0);
}

// wrong parameters: given no upstream_memory_provider
// nor init_buffer while exactly one of them must be set
TEST_P(CoarseWithMemoryStrategyTest, coarseProvider_wrong_params_0) {
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
TEST_P(CoarseWithMemoryStrategyTest, coarseProvider_wrong_params_1) {
    umf_memory_provider_handle_t malloc_memory_provider;
    umf_result_t umf_result;

    umf_result = umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                                         &malloc_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(malloc_memory_provider, nullptr);

    const size_t init_buffer_size = 20 * MB;

    // preallocate some memory and initialize the vector with zeros
    std::vector<char> buffer(init_buffer_size, 0);
    void *buf = (void *)buffer.data();
    ASSERT_NE(buf, nullptr);

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
TEST_P(CoarseWithMemoryStrategyTest, coarseProvider_wrong_params_2) {
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
TEST_P(CoarseWithMemoryStrategyTest, coarseProvider_wrong_params_3) {
    umf_result_t umf_result;

    const size_t init_buffer_size = 20 * MB;

    // preallocate some memory and initialize the vector with zeros
    std::vector<char> buffer(init_buffer_size, 0);
    void *buf = (void *)buffer.data();
    ASSERT_NE(buf, nullptr);

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
TEST_P(CoarseWithMemoryStrategyTest, coarseProvider_wrong_params_4) {
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

// wrong parameters: destroy_upstream_memory_provider is true, but an upstream provider is not provided
TEST_P(CoarseWithMemoryStrategyTest, coarseProvider_wrong_params_5) {
    umf_result_t umf_result;

    const size_t init_buffer_size = 20 * MB;

    // preallocate some memory and initialize the vector with zeros
    std::vector<char> buffer(init_buffer_size, 0);
    void *buf = (void *)buffer.data();
    ASSERT_NE(buf, nullptr);

    coarse_memory_provider_params_t coarse_memory_provider_params;
    // make sure there are no undefined members - prevent a UB
    memset(&coarse_memory_provider_params, 0,
           sizeof(coarse_memory_provider_params));
    coarse_memory_provider_params.allocation_strategy = allocation_strategy;
    coarse_memory_provider_params.upstream_memory_provider = nullptr;
    coarse_memory_provider_params.destroy_upstream_memory_provider = true;
    coarse_memory_provider_params.immediate_init_from_upstream = false;
    coarse_memory_provider_params.init_buffer = buf;
    coarse_memory_provider_params.init_buffer_size = init_buffer_size;

    umf_memory_provider_handle_t coarse_memory_provider = nullptr;
    umf_result = umfMemoryProviderCreate(umfCoarseMemoryProviderOps(),
                                         &coarse_memory_provider_params,
                                         &coarse_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(coarse_memory_provider, nullptr);
}

TEST_P(CoarseWithMemoryStrategyTest, coarseProvider_split_merge) {
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

TEST_P(CoarseWithMemoryStrategyTest, coarseProvider_split_merge_negative) {
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

TEST_P(CoarseWithMemoryStrategyTest, coarseProvider_purge_no_upstream) {
    umf_result_t umf_result;

    const size_t init_buffer_size = 20 * MB;

    // preallocate some memory and initialize the vector with zeros
    std::vector<char> buffer(init_buffer_size, 0);
    void *buf = (void *)buffer.data();
    ASSERT_NE(buf, nullptr);

    coarse_memory_provider_params_t coarse_memory_provider_params;
    // make sure there are no undefined members - prevent a UB
    memset(&coarse_memory_provider_params, 0,
           sizeof(coarse_memory_provider_params));
    coarse_memory_provider_params.allocation_strategy = allocation_strategy;
    coarse_memory_provider_params.upstream_memory_provider = nullptr;
    coarse_memory_provider_params.immediate_init_from_upstream = false;
    coarse_memory_provider_params.init_buffer = buf;
    coarse_memory_provider_params.init_buffer_size = init_buffer_size;

    umf_memory_provider_handle_t coarse_memory_provider = nullptr;
    umf_result = umfMemoryProviderCreate(umfCoarseMemoryProviderOps(),
                                         &coarse_memory_provider_params,
                                         &coarse_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_memory_provider, nullptr);

    // umfMemoryProviderPurgeLazy
    // provider == NULL
    umf_result = umfMemoryProviderPurgeLazy(nullptr, (void *)0x01, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // ptr == NULL
    umf_result = umfMemoryProviderPurgeLazy(coarse_memory_provider, nullptr, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // no upstream_memory_provider
    umf_result =
        umfMemoryProviderPurgeLazy(coarse_memory_provider, (void *)0x01, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    // umfMemoryProviderPurgeForce
    // provider == NULL
    umf_result = umfMemoryProviderPurgeForce(nullptr, (void *)0x01, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // ptr == NULL
    umf_result =
        umfMemoryProviderPurgeForce(coarse_memory_provider, nullptr, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // no upstream_memory_provider
    umf_result =
        umfMemoryProviderPurgeForce(coarse_memory_provider, (void *)0x01, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    umfMemoryProviderDestroy(coarse_memory_provider);
}

TEST_P(CoarseWithMemoryStrategyTest, coarseProvider_purge_with_upstream) {
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

    // umfMemoryProviderPurgeLazy
    // provider == NULL
    umf_result = umfMemoryProviderPurgeLazy(nullptr, (void *)0x01, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // ptr == NULL
    umf_result = umfMemoryProviderPurgeLazy(coarse_memory_provider, nullptr, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // malloc_memory_provider returns UMF_RESULT_ERROR_UNKNOWN
    umf_result =
        umfMemoryProviderPurgeLazy(coarse_memory_provider, (void *)0x01, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_UNKNOWN);

    // umfMemoryProviderPurgeForce
    // provider == NULL
    umf_result = umfMemoryProviderPurgeForce(nullptr, (void *)0x01, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // ptr == NULL
    umf_result =
        umfMemoryProviderPurgeForce(coarse_memory_provider, nullptr, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // malloc_memory_provider returns UMF_RESULT_ERROR_UNKNOWN
    umf_result =
        umfMemoryProviderPurgeForce(coarse_memory_provider, (void *)0x01, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_UNKNOWN);

    umfMemoryProviderDestroy(coarse_memory_provider);
    umfMemoryProviderDestroy(malloc_memory_provider);
}
