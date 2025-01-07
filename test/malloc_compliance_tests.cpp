// Copyright (C) 2023-2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

// Basic tests
// ISO/IEC 9899:201x 7.22.3 compliance

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "malloc_compliance_tests.hpp"
#include "test_helpers.h"
#include "umf/memory_pool.h"

#include "base.hpp"
using umf_test::test;

#define ALLOC_MIN_ALIGNMENT 8

//------------------------------------------------------------------------
// Configurable defs
//------------------------------------------------------------------------

#define MAX_ALLOC_SIZE (1024 * 1024) // 1 MB
#define ITERATIONS 100
#define SRAND_INIT_VALUE 0

//------------------------------------------------------------------------
// Helpers
//------------------------------------------------------------------------

static inline size_t rand_alloc_size(int max) { return rand() % max; }

static inline void free_memory(umf_memory_pool_handle_t hPool,
                               void *ptr[ITERATIONS]) {
    for (int i = 0; i < ITERATIONS; i++) {
        umfPoolFree(hPool, ptr[i]);
    }
}

//------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

// ISO/IEC 9899:TC3 7.20.3.3
void malloc_compliance_test(umf_memory_pool_handle_t hPool) {
    srand(SRAND_INIT_VALUE);
    void *alloc_ptr[ITERATIONS];
    size_t alloc_ptr_size[ITERATIONS];

    // Each allocation shall yield a pointer to an object disjoint from
    // any other object.
    for (int i = 0; i < ITERATIONS; i++) {
        alloc_ptr_size[i] = rand_alloc_size(MAX_ALLOC_SIZE);
        alloc_ptr[i] = umfPoolMalloc(hPool, alloc_ptr_size[i]);

        ASSERT_NE(addressIsAligned(alloc_ptr[i], ALLOC_MIN_ALIGNMENT), 0)
            << "Malloc should return pointer that is suitably aligned so that "
               "it may be assigned to a pointer to any type of object";

        // Fill memory with a pattern ((id of the allocation) % 256)
        ASSERT_NE(alloc_ptr[i], nullptr)
            << "malloc returned NULL, couldn't allocate much memory";
        memset(alloc_ptr[i], i % 0xFF, alloc_ptr_size[i]);
    }
    for (int i = 0; i < ITERATIONS; i++) {
        ASSERT_NE(
            bufferIsFilledWithChar(alloc_ptr[i], alloc_ptr_size[i], i % 0xFF),
            0)
            << "Object returned by malloc is not disjoined from others";
        memset(alloc_ptr[i], 1, alloc_ptr_size[i]);
    }
    free_memory(hPool, alloc_ptr);
}

// ISO/IEC 9899:TC3 7.20.3.1
void calloc_compliance_test(umf_memory_pool_handle_t hPool) {
    srand(SRAND_INIT_VALUE);
    void *alloc_ptr[ITERATIONS];
    size_t alloc_size;

    // Checking that the memory returned by calloc is zero filled
    for (int i = 0; i < ITERATIONS; i++) {
        alloc_size = rand_alloc_size(MAX_ALLOC_SIZE);
        alloc_ptr[i] = umfPoolCalloc(hPool, 2, alloc_size);

        ASSERT_NE(alloc_ptr[i], nullptr)
            << "calloc returned NULL, couldn't allocate much memory";
        ASSERT_NE(bufferIsFilledWithChar(alloc_ptr[i], 2 * alloc_size, 0), 0)
            << "Memory returned by calloc was not zeroed";
    }
    free_memory(hPool, alloc_ptr);
}

// ISO/IEC 9899:TC3 7.20.3.4
void realloc_compliance_test(umf_memory_pool_handle_t hPool) {
    srand(SRAND_INIT_VALUE);
    // If ptr is a null pointer, the realloc function behaves
    // like the malloc function for the specified size
    void *ret = umfPoolRealloc(hPool, NULL, 10);
    ASSERT_NE(ret, nullptr)
        << "If ptr is a NULL, realloc should behave like malloc";
    // SIGSEGV if memory was allocated wrong
    memset(ret, 1, 10);
    umfPoolFree(hPool, ret);

    // The contents of the new object shall be the same
    // as that of the old object prior to deallocation
    void *realloc_ptr[ITERATIONS];
    size_t alloc_size;
    for (int i = 0; i < ITERATIONS; i++) {
        // Generate allocation size
        alloc_size = rand_alloc_size(MAX_ALLOC_SIZE);
        void *malloc_obj = umfPoolMalloc(hPool, alloc_size);
        ASSERT_NE(malloc_obj, nullptr)
            << "malloc returned NULL, couldn't allocate much memory";

        // Fit memory region with data and store
        // it's content somehere before realloc
        void *saved_obj = umfPoolMalloc(hPool, alloc_size);
        ASSERT_NE(saved_obj, nullptr)
            << "malloc returned NULL, couldn't allocate much memory";
        memset(malloc_obj, 1, alloc_size);
        memcpy(saved_obj, malloc_obj, alloc_size);

        // Reallocate with 100 byte size increasing
        realloc_ptr[i] = umfPoolRealloc(hPool, malloc_obj, alloc_size + 100);
        ASSERT_NE(buffersHaveSameContent(realloc_ptr[i], saved_obj, alloc_size),
                  0)
            << "Content after realloc should remain the same";

        // Delete saved memory
        umfPoolFree(hPool, saved_obj);
    }
    free_memory(hPool, realloc_ptr);
}

// ISO/IEC 9899:TC3 7.20.3.2
void free_compliance_test(umf_memory_pool_handle_t hPool) {
    // If ptr is a null pointer, no action occurs
    errno = 0;
    for (int i = 0; i < ITERATIONS; i++) {
        umfPoolFree(hPool, NULL);
    }
    ASSERT_EQ(errno, 0) << "Error was found by a free call with NULL parameter";
}
