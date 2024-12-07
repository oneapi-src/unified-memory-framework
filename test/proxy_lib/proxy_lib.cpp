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

#define SIZE_64 64
#define ALIGN_1024 1024

TEST_F(test, proxyLib_basic) {

    ::free(::malloc(SIZE_64));

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
    // realloc(ptr, 0) == free (ptr)
    // realloc(ptr, 0) returns NULL
    ASSERT_EQ(::realloc(::malloc(SIZE_64), 0), nullptr);
}

TEST_F(test, proxyLib_malloc_usable_size) {

    void *ptr = ::malloc(SIZE_64);
    ASSERT_NE(ptr, nullptr);
    if (ptr == nullptr) {
        // Fix for the following CodeQL's warning on Windows:
        // 'ptr' could be '0': this does not adhere to the specification for the function '_msize'.
        return;
    }

#ifdef _WIN32
    size_t size = _msize(ptr);
#elif __APPLE__
    size_t size = ::malloc_size(ptr);
#else
    size_t size = ::malloc_usable_size(ptr);
#endif

    ASSERT_EQ((int)(size == 0 || size >= SIZE_64), 1);

    ::free(ptr);
}

TEST_F(test, proxyLib_aligned_alloc) {
#ifdef _WIN32
    void *ptr = _aligned_malloc(SIZE_64, ALIGN_1024);
#else
    void *ptr = ::aligned_alloc(ALIGN_1024, SIZE_64);
#endif

    ASSERT_EQ((int)(IS_ALIGNED((uintptr_t)ptr, ALIGN_1024)), 1);

#ifdef _WIN32
    _aligned_free(ptr);
#else
    ::free(ptr);
#endif
}
