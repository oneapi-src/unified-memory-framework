/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#if defined(__APPLE__)
#include <malloc/malloc.h>
#else
#include <malloc.h>
#endif

#include <umf/proxy_lib_new_delete.h>

#include "base.hpp"
#include "test_helpers.h"
#include "utils_common.h"

using umf_test::test;

// size threshold defined by the env variable UMF_PROXY="size.threshold=64"
#define SIZE_THRESHOLD 64
#define SIZE_EQ (SIZE_THRESHOLD)
#define SIZE_LT (SIZE_THRESHOLD - 1)

#define ALIGN_1024 1024

TEST_F(test, proxyLib_basic) {
    // a check to verify we are running the proxy library
    void *ptr = (void *)0x01;

#ifdef _WIN32
    size_t size = _msize(ptr);
#elif __APPLE__
    size_t size = ::malloc_size(ptr);
#else
    size_t size = ::malloc_usable_size(ptr);
#endif

    ASSERT_EQ(size, 0xDEADBEEF);
}

TEST_F(test, proxyLib_realloc_size0) {
    // realloc(ptr, 0) == free(ptr)
    // realloc(ptr, 0) returns NULL
    ASSERT_EQ(::realloc(::malloc(SIZE_EQ), 0), nullptr);
}

// The proxyLib_size_threshold_* tests test the size threshold of the proxy library.
// The size threshold is set to SIZE_THRESHOLD bytes in this test, so all allocations of:
// 1) size <  SIZE_THRESHOLD go through the default system allocator
//    (umfPoolByPtr(ptr_size < SIZE_THRESHOLD) == nullptr)
// 2) size >= SIZE_THRESHOLD go through the proxy library allocator
//    (umfPoolByPtr(ptr_size >= SIZE_THRESHOLD) != nullptr)

TEST_F(test, proxyLib_size_threshold_aligned_alloc) {
#ifdef _WIN32
    void *ptr_LT = _aligned_malloc(SIZE_LT, ALIGN_1024);
    void *ptr_EQ = _aligned_malloc(SIZE_EQ, ALIGN_1024);
#else
    void *ptr_LT = ::aligned_alloc(ALIGN_1024, SIZE_LT);
    void *ptr_EQ = ::aligned_alloc(ALIGN_1024, SIZE_EQ);
#endif

    ASSERT_NE(ptr_LT, nullptr);
    ASSERT_NE(ptr_EQ, nullptr);

    // verify alignment
    ASSERT_EQ((int)(IS_ALIGNED((uintptr_t)ptr_LT, ALIGN_1024)), 1);
    ASSERT_EQ((int)(IS_ALIGNED((uintptr_t)ptr_EQ, ALIGN_1024)), 1);

    ASSERT_EQ(umfPoolByPtr(ptr_LT), nullptr);
    ASSERT_NE(umfPoolByPtr(ptr_EQ), nullptr);

#ifdef _WIN32
    _aligned_free(ptr_LT);
    _aligned_free(ptr_EQ);
#else
    ::free(ptr_LT);
    ::free(ptr_EQ);
#endif
}

TEST_F(test, proxyLib_size_threshold_malloc) {
    void *ptr_LT = malloc(SIZE_LT);
    void *ptr_EQ = malloc(SIZE_EQ);

    ASSERT_NE(ptr_LT, nullptr);
    ASSERT_NE(ptr_EQ, nullptr);

    ASSERT_EQ(umfPoolByPtr(ptr_LT), nullptr);
    ASSERT_NE(umfPoolByPtr(ptr_EQ), nullptr);

    ::free(ptr_LT);
    ::free(ptr_EQ);
}

TEST_F(test, proxyLib_size_threshold_calloc) {
    void *ptr_LT = calloc(SIZE_LT, 1);
    void *ptr_EQ = calloc(SIZE_EQ, 1);

    ASSERT_NE(ptr_LT, nullptr);
    ASSERT_NE(ptr_EQ, nullptr);

    ASSERT_EQ(umfPoolByPtr(ptr_LT), nullptr);
    ASSERT_NE(umfPoolByPtr(ptr_EQ), nullptr);

    ::free(ptr_LT);
    ::free(ptr_EQ);
}

TEST_F(test, proxyLib_size_threshold_realloc_up) {
    void *ptr_LT = malloc(SIZE_LT);
    void *ptr_EQ = malloc(SIZE_EQ);

    ASSERT_NE(ptr_LT, nullptr);
    ASSERT_NE(ptr_EQ, nullptr);

    void *ptr_LT_r = realloc(ptr_LT, 2 * SIZE_LT);
    void *ptr_EQ_r = realloc(ptr_EQ, 2 * SIZE_EQ);

    ASSERT_NE(ptr_LT_r, nullptr);
    ASSERT_NE(ptr_EQ_r, nullptr);

    ASSERT_EQ(umfPoolByPtr(ptr_LT_r), nullptr);
    ASSERT_NE(umfPoolByPtr(ptr_EQ_r), nullptr);

    ::free(ptr_LT_r);
    ::free(ptr_EQ_r);
}

TEST_F(test, proxyLib_size_threshold_realloc_down) {
    void *ptr_LT = malloc(SIZE_LT);
    void *ptr_EQ = malloc(SIZE_EQ);

    ASSERT_NE(ptr_LT, nullptr);
    ASSERT_NE(ptr_EQ, nullptr);

    void *ptr_LT_r = realloc(ptr_LT, SIZE_LT / 2);
    void *ptr_EQ_r = realloc(ptr_EQ, SIZE_EQ / 2);

    ASSERT_NE(ptr_LT_r, nullptr);
    ASSERT_NE(ptr_EQ_r, nullptr);

    ASSERT_EQ(umfPoolByPtr(ptr_LT_r), nullptr);
    ASSERT_NE(umfPoolByPtr(ptr_EQ_r), nullptr);

    ::free(ptr_LT_r);
    ::free(ptr_EQ_r);
}

TEST_F(test, proxyLib_size_threshold_malloc_usable_size) {

    void *ptr_LT = ::malloc(SIZE_LT);
    void *ptr_EQ = ::malloc(SIZE_EQ);

    ASSERT_NE(ptr_LT, nullptr);
    ASSERT_NE(ptr_EQ, nullptr);

    if (ptr_LT == nullptr || ptr_EQ == nullptr) {
        // Fix for the following CodeQL's warning on Windows:
        // 'ptr' could be '0': this does not adhere to the specification for the function '_msize'.
        return;
    }

#ifdef _WIN32
    size_t size_LT = _msize(ptr_LT);
    size_t size_EQ = _msize(ptr_EQ);
#elif __APPLE__
    size_t size_LT = ::malloc_size(ptr_LT);
    size_t size_EQ = ::malloc_size(ptr_EQ);
#else
    size_t size_LT = ::malloc_usable_size(ptr_LT);
    size_t size_EQ = ::malloc_usable_size(ptr_EQ);
#endif

    ASSERT_EQ((int)(size_LT == 0 || size_LT >= SIZE_LT), 1);
    ASSERT_EQ((int)(size_EQ == 0 || size_EQ >= SIZE_EQ), 1);

    ::free(ptr_LT);
    ::free(ptr_EQ);
}
