/*
 * Copyright (C) 2024-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include "coarse.h"
#include "provider.hpp"

using umf_test::KB;
using umf_test::MB;
using umf_test::test;

#define MOCKED_COARSE ((coarse_t *)0x01)
#define MOCKED_PROVIDER ((umf_memory_provider_handle_t)0x02)
#define INVALID_PTR ((void *)0x03)

static umf_result_t alloc_cb(void *provider, size_t size, size_t alignment,
                             void **ptr) {
    return umfMemoryProviderAlloc((umf_memory_provider_handle_t)provider, size,
                                  alignment, ptr);
}

static umf_result_t free_cb(void *provider, void *ptr, size_t size) {
    return umfMemoryProviderFree((umf_memory_provider_handle_t)provider, ptr,
                                 size);
}

static umf_result_t split_cb(void *provider, void *ptr, size_t totalSize,
                             size_t firstSize) {
    if (provider == NULL || ptr == NULL || (firstSize >= totalSize) ||
        firstSize == 0 || totalSize == 0) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    return UMF_RESULT_SUCCESS;
}

static umf_result_t merge_cb(void *provider, void *lowPtr, void *highPtr,
                             size_t totalSize) {
    if (provider == NULL || lowPtr == NULL || highPtr == NULL ||
        totalSize == 0 || ((uintptr_t)highPtr <= (uintptr_t)lowPtr) ||
        ((uintptr_t)highPtr - (uintptr_t)lowPtr >= totalSize)) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    return UMF_RESULT_SUCCESS;
}

static umf_result_t alloc_cb_fails(void *provider, size_t size,
                                   size_t alignment, void **ptr) {
    (void)provider;  //unused
    (void)size;      //unused
    (void)alignment; //unused
    (void)ptr;       //unused
    return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
}

static umf_result_t free_cb_fails(void *provider, void *ptr, size_t size) {
    (void)provider; //unused
    (void)ptr;      //unused
    (void)size;     //unused
    return UMF_RESULT_ERROR_USER_SPECIFIC;
}

static umf_result_t split_cb_fails(void *provider, void *ptr, size_t totalSize,
                                   size_t firstSize) {
    (void)provider;  //unused
    (void)ptr;       //unused
    (void)totalSize; //unused
    (void)firstSize; //unused
    return UMF_RESULT_ERROR_USER_SPECIFIC;
}

static umf_result_t merge_cb_fails(void *provider, void *lowPtr, void *highPtr,
                                   size_t totalSize) {
    (void)provider;  //unused
    (void)lowPtr;    //unused
    (void)highPtr;   //unused
    (void)totalSize; //unused
    return UMF_RESULT_ERROR_USER_SPECIFIC;
}

static void coarse_params_set_default(coarse_params_t *coarse_params,
                                      umf_memory_provider_handle_t provider,
                                      coarse_strategy_t allocation_strategy) {
    memset(coarse_params, 0, sizeof(*coarse_params));
    coarse_params->provider = provider;
    coarse_params->allocation_strategy = allocation_strategy;
    coarse_params->cb.split = split_cb;
    coarse_params->cb.merge = merge_cb;
    coarse_params->page_size = utils_get_page_size();

    if (provider) {
        coarse_params->cb.alloc = alloc_cb;
        coarse_params->cb.free = free_cb;
    }
}

umf_memory_provider_ops_t UMF_MALLOC_MEMORY_PROVIDER_OPS =
    umf::providerMakeCOps<umf_test::provider_ba_global, void>();

struct CoarseWithMemoryStrategyTest
    : umf_test::test,
      ::testing::WithParamInterface<coarse_strategy_t> {
    void SetUp() override {
        test::SetUp();
        allocation_strategy = this->GetParam();
        coarse_params_set_default(&coarse_params, MOCKED_PROVIDER,
                                  allocation_strategy);
    }

    coarse_t *coarse_handle = nullptr;
    coarse_params_t coarse_params;
    coarse_strategy_t allocation_strategy;
    umf_result_t umf_result;
};

INSTANTIATE_TEST_SUITE_P(
    CoarseWithMemoryStrategyTest, CoarseWithMemoryStrategyTest,
    ::testing::Values(UMF_COARSE_MEMORY_STRATEGY_FASTEST,
                      UMF_COARSE_MEMORY_STRATEGY_FASTEST_BUT_ONE,
                      UMF_COARSE_MEMORY_STRATEGY_CHECK_ALL_SIZE));

TEST_P(CoarseWithMemoryStrategyTest, coarseTest_basic_provider) {
    umf_memory_provider_handle_t malloc_memory_provider;
    umf_result = umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                                         &malloc_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(malloc_memory_provider, nullptr);

    coarse_params.provider = malloc_memory_provider;

    umf_result = coarse_new(&coarse_params, &coarse_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_handle, nullptr);

    coarse_t *ch = coarse_handle;
    const size_t alloc_size = 20 * MB;
    void *ptr;

    umf_result = coarse_add_memory_from_provider(ch, alloc_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    umf_result = coarse_alloc(ch, 2 * MB, 0, (void **)&ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 2 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 2);

    umf_result = coarse_free(ch, ptr, 2 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 0);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    coarse_delete(ch);
    umfMemoryProviderDestroy(malloc_memory_provider);
}

TEST_P(CoarseWithMemoryStrategyTest, coarseTest_basic_fixed_memory) {
    // preallocate some memory and initialize the vector with zeros
    const size_t buff_size = 20 * MB + coarse_params.page_size;
    std::vector<char> buffer(buff_size, 0);
    void *buf = (void *)ALIGN_UP_SAFE((uintptr_t)buffer.data(),
                                      coarse_params.page_size);
    ASSERT_NE(buf, nullptr);

    coarse_params.cb.alloc = NULL;
    coarse_params.cb.free = NULL;

    umf_result = coarse_new(&coarse_params, &coarse_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_handle, nullptr);

    coarse_t *ch = coarse_handle;
    char *ptr = nullptr;

    umf_result = coarse_add_memory_fixed(ch, buf, buff_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, buff_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    umf_result = coarse_alloc(ch, 2 * MB, 0, (void **)&ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 2 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, buff_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 2);

    umf_result = coarse_free(ch, ptr, 2 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 0);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, buff_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    coarse_delete(ch);
}

TEST_P(CoarseWithMemoryStrategyTest, coarseTest_fixed_memory_various) {
    // preallocate some memory and initialize the vector with zeros
    const size_t buff_size = 20 * MB + coarse_params.page_size;
    std::vector<char> buffer(buff_size, 0);
    void *buf = (void *)ALIGN_UP_SAFE((uintptr_t)buffer.data(),
                                      coarse_params.page_size);
    ASSERT_NE(buf, nullptr);

    coarse_params.cb.alloc = NULL;
    coarse_params.cb.free = NULL;

    umf_result = coarse_new(&coarse_params, &coarse_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_handle, nullptr);

    coarse_t *ch = coarse_handle;
    char *ptr = nullptr;

    umf_result = coarse_add_memory_fixed(ch, buf, buff_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, buff_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    // free NULL
    umf_result = coarse_free(ch, nullptr, 2 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    // free invalid pointer
    umf_result = coarse_free(ch, INVALID_PTR, 2 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // wrong alignment (3 bytes)
    ptr = nullptr;
    umf_result = coarse_alloc(ch, 2 * MB, 3, (void **)&ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ALIGNMENT);
    ASSERT_EQ(ptr, nullptr);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 0);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, buff_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    // not freed allocation
    // coarse_delete() prints LOG_WARN() in Debug mode
    umf_result = coarse_alloc(ch, 2 * MB, 0, (void **)&ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 2 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, buff_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 2);

    coarse_delete(ch);
}

TEST_P(CoarseWithMemoryStrategyTest, coarseTest_split_merge) {
    umf_memory_provider_handle_t malloc_memory_provider;
    umf_result = umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                                         &malloc_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(malloc_memory_provider, nullptr);

    coarse_params.provider = malloc_memory_provider;

    umf_result = coarse_new(&coarse_params, &coarse_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_handle, nullptr);

    coarse_t *ch = coarse_handle;
    char *ptr = nullptr;
    const size_t alloc_size = 20 * MB;

    umf_result = coarse_add_memory_from_provider(ch, alloc_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    /* test coarse_split */
    umf_result = coarse_alloc(ch, 2 * MB, 0, (void **)&ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 2 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 2);

    umf_result = coarse_split(ch, ptr, 2 * MB, 1 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 2 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 3);

    umf_result = coarse_free(ch, (ptr + 1 * MB), 1 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 1 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 2);

    umf_result = coarse_free(ch, ptr, 1 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 0);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    /* test coarse_merge */
    umf_result = coarse_alloc(ch, 2 * MB, 0, (void **)&ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 2 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 2);

    umf_result = coarse_split(ch, ptr, 2 * MB, 1 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 2 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 3);

    umf_result = coarse_merge(ch, ptr, (ptr + 1 * MB), 2 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 2 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 2);

    umf_result = coarse_free(ch, ptr, 2 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 0);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    coarse_delete(coarse_handle);
    umfMemoryProviderDestroy(malloc_memory_provider);
}

// negative tests

// NULL parameters
TEST_P(CoarseWithMemoryStrategyTest, coarseTest_no_params) {
    umf_result = coarse_new(nullptr, &coarse_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(coarse_handle, nullptr);
}

// no provider
TEST_P(CoarseWithMemoryStrategyTest, coarseTest_no_provider) {
    coarse_params.provider = NULL;
    umf_result = coarse_new(&coarse_params, &coarse_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(coarse_handle, nullptr);
}

// no page size
TEST_P(CoarseWithMemoryStrategyTest, coarseTest_no_page_size) {
    coarse_params.page_size = 0;
    umf_result = coarse_new(&coarse_params, &coarse_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(coarse_handle, nullptr);
}

// no split callback
TEST_P(CoarseWithMemoryStrategyTest, coarseTest_no_split_cb) {
    coarse_params.cb.split = NULL;
    umf_result = coarse_new(&coarse_params, &coarse_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(coarse_handle, nullptr);
}

// no merge callback
TEST_P(CoarseWithMemoryStrategyTest, coarseTest_no_merge_cb) {
    coarse_params.cb.merge = NULL;
    umf_result = coarse_new(&coarse_params, &coarse_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(coarse_handle, nullptr);
}

TEST_P(CoarseWithMemoryStrategyTest, coarseTest_alloc_invalid) {
    void *ptr = nullptr;

    umf_result = coarse_alloc(nullptr, MB, 0, nullptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(ptr, nullptr);

    umf_result = coarse_alloc(nullptr, MB, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(ptr, nullptr);

    umf_result = coarse_alloc(MOCKED_COARSE, MB, 0, nullptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(ptr, nullptr);
}

TEST_P(CoarseWithMemoryStrategyTest, coarseTest_free_invalid) {
    // coarse handle is NULL
    umf_result = coarse_free(nullptr, nullptr, MB);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_P(CoarseWithMemoryStrategyTest, coarseTest_delete_null) {
    coarse_delete(nullptr);
}

TEST_P(CoarseWithMemoryStrategyTest,
       coarseTest_add_memory_from_provider_null_0) {
    umf_result = coarse_add_memory_from_provider(nullptr, 0);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_P(CoarseWithMemoryStrategyTest, coarseTest_add_memory_fixed_null_0) {
    umf_result = coarse_add_memory_fixed(nullptr, nullptr, 0);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_P(CoarseWithMemoryStrategyTest, coarseTest_null_stats) {
    ASSERT_EQ(coarse_get_stats(nullptr).alloc_size, 0);
    ASSERT_EQ(coarse_get_stats(nullptr).used_size, 0);
    ASSERT_EQ(coarse_get_stats(nullptr).num_all_blocks, 0);
    ASSERT_EQ(coarse_get_stats(nullptr).num_free_blocks, 0);
}

TEST_P(CoarseWithMemoryStrategyTest, coarseTest_split_merge_negative) {
    umf_memory_provider_handle_t malloc_memory_provider;
    umf_result = umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                                         &malloc_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(malloc_memory_provider, nullptr);

    coarse_params.provider = malloc_memory_provider;

    umf_result = coarse_new(&coarse_params, &coarse_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_handle, nullptr);

    coarse_t *ch = coarse_handle;
    char *ptr = nullptr;
    const size_t alloc_size = 20 * MB;

    umf_result = coarse_add_memory_from_provider(ch, alloc_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    /* test coarse_split */

    umf_result = coarse_alloc(ch, 6 * MB, 0, (void **)&ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 6 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 2);

    // firstSize >= totalSize
    umf_result = coarse_split(ch, ptr, 6 * MB, 6 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // firstSize == 0
    umf_result = coarse_split(ch, ptr, 6 * MB, 0);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // totalSize == 0
    umf_result = coarse_split(ch, ptr, 0, 1 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // wrong totalSize
    umf_result = coarse_split(ch, ptr, 5 * MB, 1 * KB);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // memory block not found
    umf_result = coarse_split(ch, ptr + 1, 6 * MB, 1 * KB);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umf_result = coarse_free(ch, ptr, 6 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    // split freed block
    umf_result = coarse_split(ch, ptr, alloc_size, 1 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    /* test coarse_merge */

    umf_result = coarse_alloc(ch, 6 * MB, 0, (void **)&ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 6 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 2);

    // split (6 * MB) block into (1 * MB) + (5 * MB)
    umf_result = coarse_split(ch, ptr, 6 * MB, 1 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 6 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 3);

    // split (5 * MB) block into (2 * MB) + (3 * MB)
    umf_result = coarse_split(ch, (ptr + 1 * MB), 5 * MB, 2 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 6 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 4);

    // now we have 3 used blocks: (1 * MB) + (2 * MB) + (3 * MB)

    // highPtr <= lowPtr
    umf_result = coarse_merge(ch, (ptr + 1 * MB), ptr, 2 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // highPtr - lowPtr >= totalSize
    umf_result = coarse_merge(ch, ptr, (ptr + 1 * MB), 1 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // low ptr does not exist
    umf_result = coarse_merge(ch, ptr + 1, (ptr + 1 * MB), 3 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // high ptr does not exist
    umf_result = coarse_merge(ch, ptr, (ptr + 1 * MB + 1), 3 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // low_block->size + high_block->size != totalSize
    umf_result = coarse_merge(ch, ptr, (ptr + 1 * MB), 5 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // not adjacent blocks
    umf_result = coarse_merge(ch, ptr, (ptr + 3 * MB), 4 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // free the 2 MB block in the middle
    umf_result = coarse_free(ch, (ptr + 1 * MB), 2 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 4 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 4);

    // now we have 3 blocks: (1 * MB) used + (2 * MB) freed + (3 * MB) used

    // the low ptr block is not allocated
    umf_result = coarse_merge(ch, (ptr + 1 * MB), (ptr + 3 * MB), 5 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // the high ptr block is not allocated
    umf_result = coarse_merge(ch, ptr, (ptr + 1 * MB), 3 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umf_result = coarse_free(ch, ptr, 1 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 3 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 3);

    umf_result = coarse_free(ch, (ptr + 3 * MB), 3 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 0);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    coarse_delete(coarse_handle);
    umfMemoryProviderDestroy(malloc_memory_provider);
}

TEST_P(CoarseWithMemoryStrategyTest, coarseTest_basic_alloc_cb_fails) {
    umf_memory_provider_handle_t malloc_memory_provider;
    umf_result = umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                                         &malloc_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(malloc_memory_provider, nullptr);

    coarse_params.provider = malloc_memory_provider;
    coarse_params.cb.alloc = alloc_cb_fails;

    umf_result = coarse_new(&coarse_params, &coarse_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_handle, nullptr);

    coarse_t *ch = coarse_handle;
    const size_t alloc_size = 20 * MB;

    umf_result = coarse_add_memory_from_provider(ch, alloc_size);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY);

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, 0);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 0);

    coarse_delete(ch);
    umfMemoryProviderDestroy(malloc_memory_provider);
}

TEST_P(CoarseWithMemoryStrategyTest, coarseTest_basic_free_cb_fails) {
    umf_memory_provider_handle_t malloc_memory_provider;
    umf_result = umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                                         &malloc_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(malloc_memory_provider, nullptr);

    coarse_params.provider = malloc_memory_provider;
    coarse_params.cb.free = free_cb_fails;

    umf_result = coarse_new(&coarse_params, &coarse_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_handle, nullptr);

    coarse_t *ch = coarse_handle;
    const size_t alloc_size = 20 * MB;

    umf_result = coarse_add_memory_from_provider(ch, alloc_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    coarse_delete(ch);
    umfMemoryProviderDestroy(malloc_memory_provider);
}

TEST_P(CoarseWithMemoryStrategyTest, coarseTest_split_cb_fails) {
    if (coarse_params.allocation_strategy ==
        UMF_COARSE_MEMORY_STRATEGY_FASTEST) {
        // This test is designed for the UMF_COARSE_MEMORY_STRATEGY_FASTEST_BUT_ONE
        // and UMF_COARSE_MEMORY_STRATEGY_CHECK_ALL_SIZE strategies,
        // because the UMF_COARSE_MEMORY_STRATEGY_FASTEST strategy
        // looks always for a block of size greater by the page size.
        return;
    }

    umf_memory_provider_handle_t malloc_memory_provider;
    umf_result = umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                                         &malloc_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(malloc_memory_provider, nullptr);

    coarse_params.provider = malloc_memory_provider;
    coarse_params.cb.split = split_cb_fails;

    umf_result = coarse_new(&coarse_params, &coarse_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_handle, nullptr);

    coarse_t *ch = coarse_handle;
    void *ptr = nullptr;
    const size_t alloc_size = 20 * MB;

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, 0);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 0);

    umf_result = coarse_add_memory_from_provider(ch, alloc_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    // coarse_alloc(alloc_size / 2, alignment = 0)
    umf_result = coarse_alloc(ch, alloc_size / 2, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_USER_SPECIFIC);
    ASSERT_EQ(ptr, nullptr);

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    // coarse_alloc(alloc_size / 2, alignment = 2 * MB)
    umf_result = coarse_alloc(ch, alloc_size / 2, 2 * MB, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_USER_SPECIFIC);
    ASSERT_EQ(ptr, nullptr);

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    // coarse_alloc(alloc_size, alignment = 0) - OK
    umf_result = coarse_alloc(ch, alloc_size, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    ASSERT_EQ(coarse_get_stats(ch).used_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    umf_result = coarse_split(ch, ptr, alloc_size, alloc_size / 2);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_USER_SPECIFIC);

    ASSERT_EQ(coarse_get_stats(ch).used_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    umf_result = coarse_free(ch, ptr, alloc_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    coarse_delete(coarse_handle);
    umfMemoryProviderDestroy(malloc_memory_provider);
}

TEST_P(CoarseWithMemoryStrategyTest, coarseTest_merge_cb_fails) {
    // preallocate some memory and initialize the vector with zeros
    const size_t buff_size = 10 * MB + coarse_params.page_size;
    std::vector<char> buffer(buff_size, 0);
    void *buf = (void *)ALIGN_UP_SAFE((uintptr_t)buffer.data(),
                                      coarse_params.page_size);
    ASSERT_NE(buf, nullptr);

    coarse_params.cb.alloc = NULL;
    coarse_params.cb.free = NULL;
    coarse_params.cb.merge = merge_cb_fails;

    umf_result = coarse_new(&coarse_params, &coarse_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_handle, nullptr);

    coarse_t *ch = coarse_handle;
    char *ptr = nullptr;

    umf_result = coarse_add_memory_fixed(ch, buf, buff_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, buff_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    /* test coarse_merge */
    umf_result = coarse_alloc(ch, 3 * MB, 0, (void **)&ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 3 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, buff_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 2);

    umf_result = coarse_split(ch, ptr, 3 * MB, 1 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 3 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, buff_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 3);

    umf_result = coarse_merge(ch, ptr, (ptr + 1 * MB), 3 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_USER_SPECIFIC);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 3 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, buff_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 3);

    umf_result = coarse_free(ch, ptr, 3 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 3 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, buff_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 3);

    umf_result = coarse_free(ch, ptr, 1 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 2 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, buff_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 3);

    umf_result = coarse_free(ch, (ptr + 1 * MB), 2 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 0);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, buff_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 3);

    coarse_delete(coarse_handle);
}

TEST_P(CoarseWithMemoryStrategyTest, coarseTest_fixed_memory_alloc_set) {
    // preallocate some memory and initialize the vector with zeros
    const size_t buff_size = 20 * MB;
    std::vector<char> buffer(buff_size, 0);
    void *buf = (void *)buffer.data();
    ASSERT_NE(buf, nullptr);

    coarse_params.cb.free = NULL;

    umf_result = coarse_new(&coarse_params, &coarse_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_handle, nullptr);

    coarse_t *ch = coarse_handle;

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, 0);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 0);

    umf_result = coarse_add_memory_fixed(ch, buf, buff_size);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, 0);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 0);

    coarse_delete(ch);
}

TEST_P(CoarseWithMemoryStrategyTest, coarseTest_fixed_memory_free_set) {
    // preallocate some memory and initialize the vector with zeros
    const size_t buff_size = 20 * MB;
    std::vector<char> buffer(buff_size, 0);
    void *buf = (void *)buffer.data();
    ASSERT_NE(buf, nullptr);

    coarse_params.cb.alloc = NULL;

    umf_result = coarse_new(&coarse_params, &coarse_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_handle, nullptr);

    coarse_t *ch = coarse_handle;

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, 0);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 0);

    umf_result = coarse_add_memory_fixed(ch, buf, buff_size);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, 0);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 0);

    coarse_delete(ch);
}

TEST_P(CoarseWithMemoryStrategyTest, coarseTest_fixed_memory_alloc_free_set) {
    // preallocate some memory and initialize the vector with zeros
    const size_t buff_size = 20 * MB;
    std::vector<char> buffer(buff_size, 0);
    void *buf = (void *)buffer.data();
    ASSERT_NE(buf, nullptr);

    umf_result = coarse_new(&coarse_params, &coarse_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_handle, nullptr);

    coarse_t *ch = coarse_handle;

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, 0);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 0);

    umf_result = coarse_add_memory_fixed(ch, buf, buff_size);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, 0);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 0);

    coarse_delete(ch);
}

TEST_P(CoarseWithMemoryStrategyTest, coarseTest_provider_alloc_not_set) {
    umf_memory_provider_handle_t malloc_memory_provider;
    umf_result = umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                                         &malloc_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(malloc_memory_provider, nullptr);

    coarse_params.provider = malloc_memory_provider;
    coarse_params.cb.alloc = NULL;

    umf_result = coarse_new(&coarse_params, &coarse_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_handle, nullptr);

    coarse_t *ch = coarse_handle;
    const size_t alloc_size = 20 * MB;
    void *ptr;

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, 0);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 0);

    umf_result = coarse_add_memory_from_provider(ch, alloc_size);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_NOT_SUPPORTED);

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, 0);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 0);

    umf_result = coarse_alloc(ch, 2 * MB, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY);
    ASSERT_EQ(ptr, nullptr);

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, 0);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 0);

    umf_result = coarse_alloc(ch, 2 * MB, 2 * MB, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY);
    ASSERT_EQ(ptr, nullptr);

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, 0);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 0);

    coarse_delete(ch);
    umfMemoryProviderDestroy(malloc_memory_provider);
}

TEST_P(CoarseWithMemoryStrategyTest, coarseTest_basic) {
    if (coarse_params.allocation_strategy ==
        UMF_COARSE_MEMORY_STRATEGY_FASTEST) {
        // This test is designed for the UMF_COARSE_MEMORY_STRATEGY_FASTEST_BUT_ONE
        // and UMF_COARSE_MEMORY_STRATEGY_CHECK_ALL_SIZE strategies,
        // because the UMF_COARSE_MEMORY_STRATEGY_FASTEST strategy
        // looks always for a block of size greater by the page size.
        return;
    }

    umf_memory_provider_handle_t malloc_memory_provider;
    umf_result = umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                                         &malloc_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(malloc_memory_provider, nullptr);

    coarse_params.provider = malloc_memory_provider;

    umf_result = coarse_new(&coarse_params, &coarse_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_handle, nullptr);

    coarse_t *ch = coarse_handle;
    const size_t init_buffer_size = 20 * MB;
    void *p1, *p2;

    umf_result = coarse_add_memory_from_provider(ch, init_buffer_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, init_buffer_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    // alloc 2x 2MB
    umf_result = coarse_alloc(ch, 2 * MB, 0, (void **)&p1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(p1, nullptr);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 2 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, init_buffer_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 2);

    umf_result = coarse_alloc(ch, 2 * MB, 0, (void **)&p2);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(p2, nullptr);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 4 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, init_buffer_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 3);
    ASSERT_NE(p1, p2);

    // swap pointers to get p1 < p2
    if (p1 > p2) {
        std::swap(p1, p2);
    }

    // free + alloc first block
    // the block should be reused
    // currently there is no purging, so the alloc size shouldn't change
    // there should be no block merging between used and not-used blocks
    umf_result = coarse_free(ch, p1, 2 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 2 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, init_buffer_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 3);

    umf_result = coarse_alloc(ch, 2 * MB, 0, (void **)&p1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(p1, nullptr);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 4 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, init_buffer_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 3);

    // free all allocs
    // overall alloc size shouldn't change
    // block p2 should merge with the prev free block p1
    // and the remaining init block
    umf_result = coarse_free(ch, p1, 2 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 3);
    umf_result = coarse_free(ch, p2, 2 * MB);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, init_buffer_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    // test allocations with alignment
    // TODO: what about holes?
    umf_result = coarse_alloc(ch, 1 * MB - 4, 128, (void **)&p1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(p1, nullptr);
    ASSERT_EQ((uintptr_t)p1 & 127, 0);

    umf_result = coarse_alloc(ch, 1 * MB - 4, 128, (void **)&p2);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(p2, nullptr);
    ASSERT_EQ((uintptr_t)p2 & 127, 0);

    umf_result = coarse_free(ch, p1, 1 * MB - 4);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    umf_result = coarse_free(ch, p2, 1 * MB - 4);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    // alloc whole buffer
    // after this, there should be one single block
    umf_result = coarse_alloc(ch, init_buffer_size, 0, (void **)&p1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(p1, nullptr);
    ASSERT_EQ(coarse_get_stats(ch).used_size, init_buffer_size);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, init_buffer_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    // free all memory
    umf_result = coarse_free(ch, p1, init_buffer_size);

    // alloc 2 MB block - the init block should be split
    umf_result = coarse_alloc(ch, 2 * MB, 0, (void **)&p1);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(p1, nullptr);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 2 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, init_buffer_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 2);

    // alloc additional 2 MB
    // the non-used block should be used
    umf_result = coarse_alloc(ch, 2 * MB, 0, (void **)&p2);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(p2, nullptr);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 4 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, init_buffer_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 3);
    ASSERT_NE(p1, p2);

    // make sure that p1 < p2
    if (p1 > p2) {
        std::swap(p1, p2);
    }

    // free blocks in order: p2, p1
    // block p1 should merge with the next block p2
    // swap pointers to get p1 < p2
    coarse_free(ch, p2, 2 * MB);
    coarse_free(ch, p1, 2 * MB);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, init_buffer_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    // alloc 10x 2 MB - this should occupy all allocated memory
    constexpr int allocs_size = 10;
    void *allocs[allocs_size] = {0};
    for (int i = 0; i < allocs_size; i++) {
        ASSERT_EQ(coarse_get_stats(ch).used_size, i * 2 * MB);
        umf_result = coarse_alloc(ch, 2 * MB, 0, &allocs[i]);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        ASSERT_NE(allocs[i], nullptr);
    }
    ASSERT_EQ(coarse_get_stats(ch).used_size, 20 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, init_buffer_size);
    // there should be no block with the free memory
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, allocs_size);

    // free all memory
    for (int i = 0; i < allocs_size; i++) {
        umf_result = coarse_free(ch, allocs[i], 2 * MB);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    }

    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);
    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, init_buffer_size);

    coarse_delete(ch);
    umfMemoryProviderDestroy(malloc_memory_provider);
}

TEST_P(CoarseWithMemoryStrategyTest, coarseTest_simple1) {
    if (coarse_params.allocation_strategy ==
        UMF_COARSE_MEMORY_STRATEGY_FASTEST) {
        // This test is designed for the UMF_COARSE_MEMORY_STRATEGY_FASTEST_BUT_ONE
        // and UMF_COARSE_MEMORY_STRATEGY_CHECK_ALL_SIZE strategies,
        // because the UMF_COARSE_MEMORY_STRATEGY_FASTEST strategy
        // looks always for a block of size greater by the page size.
        return;
    }

    umf_memory_provider_handle_t malloc_memory_provider;
    umf_result = umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                                         &malloc_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(malloc_memory_provider, nullptr);

    coarse_params.provider = malloc_memory_provider;

    umf_result = coarse_new(&coarse_params, &coarse_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_handle, nullptr);

    coarse_t *ch = coarse_handle;
    const size_t init_buffer_size = 20 * MB;

    umf_result = coarse_add_memory_from_provider(ch, init_buffer_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, init_buffer_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

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
            umf_result = coarse_alloc(ch, s1, 0, &t[i]);
            ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
            ASSERT_NE(t[i], nullptr);
        }

        size_t alloc_size = coarse_get_stats(ch).alloc_size;
        if (alloc_size > max_alloc_size) {
            max_alloc_size = alloc_size;
        }

        for (int i = 0; i < nptrs; i++) {
            umf_result = coarse_free(ch, t[i], s1);
            ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        }
    }

    // s2
    for (int j = 0; j < nreps; j++) {
        void *t[nptrs] = {0};
        for (int i = 0; i < nptrs; i++) {
            umf_result = coarse_alloc(ch, s2, 0, &t[i]);
            ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
            ASSERT_NE(t[i], nullptr);
        }

        // all s2 should fit into single block leaved after freeing s1
        ASSERT_LE(coarse_get_stats(ch).alloc_size, max_alloc_size);

        for (int i = 0; i < nptrs; i++) {
            umf_result = coarse_free(ch, t[i], s2);
            ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        }
    }

    coarse_delete(ch);
    umfMemoryProviderDestroy(malloc_memory_provider);
}

TEST_P(CoarseWithMemoryStrategyTest, coarseTest_simple2) {
    umf_memory_provider_handle_t malloc_memory_provider;
    umf_result = umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                                         &malloc_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(malloc_memory_provider, nullptr);

    coarse_params.provider = malloc_memory_provider;

    umf_result = coarse_new(&coarse_params, &coarse_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_handle, nullptr);

    coarse_t *ch = coarse_handle;
    const size_t init_buffer_size = 20 * MB;

    umf_result = coarse_add_memory_from_provider(ch, init_buffer_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, init_buffer_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    // test
    double sizes[] = {2, 4, 0.5, 1, 8, 0.25};
    size_t alignment[] = {0, 4, 0, 16, 32, 128};
    for (int i = 0; i < 6; i++) {
        size_t s = (size_t)(sizes[i] * MB);
        void *t[8] = {0};
        for (int j = 0; j < 8; j++) {
            umf_result = coarse_alloc(ch, s, alignment[i], &t[j]);
            ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
            ASSERT_NE(t[j], nullptr);
        }

        for (int j = 0; j < 8; j++) {
            umf_result = coarse_free(ch, t[j], s);
            ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        }
    }

    coarse_delete(ch);
    umfMemoryProviderDestroy(malloc_memory_provider);
}

TEST_P(CoarseWithMemoryStrategyTest, coarseTest_alignment_provider) {
    umf_memory_provider_handle_t malloc_memory_provider;
    umf_result = umfMemoryProviderCreate(&UMF_MALLOC_MEMORY_PROVIDER_OPS, NULL,
                                         &malloc_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(malloc_memory_provider, nullptr);

    coarse_params.provider = malloc_memory_provider;

    umf_result = coarse_new(&coarse_params, &coarse_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_handle, nullptr);

    coarse_t *ch = coarse_handle;
    const size_t alloc_size = 40 * MB;

    umf_result = coarse_add_memory_from_provider(ch, alloc_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    const int niter = 10;
    const int size = 1 * MB;
    void *ptr[niter] = {0};

    for (int i = 0; i < niter; i++) {
        umf_result = coarse_alloc(ch, size, 0, &ptr[i]);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        ASSERT_NE(ptr[i], nullptr);
    }

    ASSERT_EQ(coarse_get_stats(ch).used_size, niter * size);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, niter + 1);

    for (int i = 0; i < niter; i += 2) {
        umf_result = coarse_free(ch, ptr[i], size);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        ptr[i] = nullptr;
    }

    ASSERT_EQ(coarse_get_stats(ch).used_size, niter * size / 2);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, niter + 1);

    for (int i = 0; i < niter; i += 2) {
        ASSERT_EQ(ptr[i], nullptr);
        umf_result = coarse_alloc(ch, size, 2 * MB, &ptr[i]);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        ASSERT_NE(ptr[i], nullptr);
    }

    ASSERT_EQ(coarse_get_stats(ch).used_size, niter * size);

    for (int i = 0; i < niter; i++) {
        umf_result = coarse_free(ch, ptr[i], size);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    }

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    coarse_delete(ch);
    umfMemoryProviderDestroy(malloc_memory_provider);
}

TEST_P(CoarseWithMemoryStrategyTest, coarseTest_alignment_fixed_memory) {
    // preallocate some memory and initialize the vector with zeros
    const size_t alloc_size = 40 * MB + coarse_params.page_size;
    std::vector<char> buffer(alloc_size, 0);
    void *buf = (void *)ALIGN_UP_SAFE((uintptr_t)buffer.data(),
                                      coarse_params.page_size);
    ASSERT_NE(buf, nullptr);

    coarse_params.cb.alloc = NULL;
    coarse_params.cb.free = NULL;

    umf_result = coarse_new(&coarse_params, &coarse_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_handle, nullptr);

    coarse_t *ch = coarse_handle;

    umf_result = coarse_add_memory_fixed(ch, buf, alloc_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    const int niter = 10;
    const int size = 1 * MB;
    void *ptr[niter] = {0};

    for (int i = 0; i < niter; i++) {
        umf_result = coarse_alloc(ch, size, 0, &ptr[i]);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        ASSERT_NE(ptr[i], nullptr);
    }

    ASSERT_EQ(coarse_get_stats(ch).used_size, niter * size);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, niter + 1);

    for (int i = 0; i < niter; i += 2) {
        umf_result = coarse_free(ch, ptr[i], size);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        ptr[i] = nullptr;
    }

    ASSERT_EQ(coarse_get_stats(ch).used_size, niter * size / 2);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, alloc_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, niter + 1);

    for (int i = 0; i < niter; i += 2) {
        ASSERT_EQ(ptr[i], nullptr);
        umf_result = coarse_alloc(ch, size, 2 * MB, &ptr[i]);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        ASSERT_NE(ptr[i], nullptr);
    }

    ASSERT_EQ(coarse_get_stats(ch).used_size, niter * size);

    for (int i = 0; i < niter; i++) {
        umf_result = coarse_free(ch, ptr[i], size);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    }

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    coarse_delete(ch);
}

TEST_P(CoarseWithMemoryStrategyTest,
       coarseTest_basic_non_aligned_fixed_memory) {
    // preallocate some memory and initialize the vector with zeros
    const size_t buff_size = 20 * MB + coarse_params.page_size;
    std::vector<char> buffer(buff_size, 0);

    void *buf_aligned = (void *)ALIGN_UP_SAFE((uintptr_t)buffer.data(),
                                              coarse_params.page_size);
    ASSERT_NE(buf_aligned, nullptr);

    void *buf_non_aligned = (void *)((uintptr_t)buf_aligned + 64);
    size_t buf_non_aligned_size =
        buff_size - ((uintptr_t)buf_non_aligned - (uintptr_t)buffer.data());
    buf_non_aligned_size =
        ALIGN_DOWN(buf_non_aligned_size, coarse_params.page_size);

    coarse_params.cb.alloc = NULL;
    coarse_params.cb.free = NULL;

    umf_result = coarse_new(&coarse_params, &coarse_handle);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(coarse_handle, nullptr);

    coarse_t *ch = coarse_handle;
    char *ptr = nullptr;

    umf_result =
        coarse_add_memory_fixed(ch, buf_non_aligned, buf_non_aligned_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, buf_non_aligned_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    umf_result = coarse_alloc(ch, buf_non_aligned_size, 0, (void **)&ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY);
    ASSERT_EQ(ptr, nullptr);

    ASSERT_EQ(coarse_get_stats(ch).used_size, 0 * MB);
    ASSERT_EQ(coarse_get_stats(ch).alloc_size, buf_non_aligned_size);
    ASSERT_EQ(coarse_get_stats(ch).num_all_blocks, 1);

    coarse_delete(ch);
}
