// Copyright (C) 2023 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "memspaces/memspace_numa.h"
#include "base.hpp"
#include "malloc_compliance_tests.hpp"
#include "memspace_helpers.hpp"
#include "memspace_internal.h"
#include "pool.hpp"

#include <umf/providers/provider_os_memory.h>

TEST_F(numaNodesTest, createDestroy) {
    umf_memspace_handle_t hMemspace = nullptr;
    enum umf_result_t ret = umfMemspaceCreateFromNumaArray(
        nodeIds.data(), nodeIds.size(), &hMemspace);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(hMemspace, nullptr);

    umfMemspaceDestroy(hMemspace);
}

TEST_F(numaNodesTest, createInvalidNullArray) {
    umf_memspace_handle_t hMemspace = nullptr;
    enum umf_result_t ret = umfMemspaceCreateFromNumaArray(NULL, 0, &hMemspace);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(hMemspace, nullptr);
}

TEST_F(numaNodesTest, createInvalidZeroSize) {
    umf_memspace_handle_t hMemspace = nullptr;
    enum umf_result_t ret =
        umfMemspaceCreateFromNumaArray(nodeIds.data(), 0, &hMemspace);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(hMemspace, nullptr);
}

TEST_F(numaNodesTest, createInvalidNullHandle) {
    enum umf_result_t ret =
        umfMemspaceCreateFromNumaArray(nodeIds.data(), nodeIds.size(), nullptr);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_F(memspaceNumaTest, providerFromNumaMemspace) {
    umf_memory_provider_handle_t hProvider = nullptr;
    enum umf_result_t ret =
        umfMemoryProviderCreateFromMemspace(hMemspace, nullptr, &hProvider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(hProvider, nullptr);

    umfMemoryProviderDestroy(hProvider);
}

TEST_F(memspaceNumaProviderTest, allocFree) {
    void *ptr = nullptr;
    size_t size = SIZE_4K;
    size_t alignment = 0;

    enum umf_result_t ret =
        umfMemoryProviderAlloc(hProvider, size, alignment, &ptr);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    memset(ptr, 0xFF, size);

    ret = umfMemoryProviderFree(hProvider, ptr, size);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
}

/* malloc compliance tests of memspaceNumaPoolTest */

TEST_F(memspaceNumaPoolTest, malloc_compliance) {
    malloc_compliance_test(pool);
}

TEST_F(memspaceNumaPoolTest, calloc_compliance) {
    if (!umf_test::isCallocSupported(pool)) {
        GTEST_SKIP();
    }

    calloc_compliance_test(pool);
}

TEST_F(memspaceNumaPoolTest, realloc_compliance) {
    if (!umf_test::isReallocSupported(pool)) {
        GTEST_SKIP();
    }

    realloc_compliance_test(pool);
}

TEST_F(memspaceNumaPoolTest, free_compliance) { free_compliance_test(pool); }

/* malloc compliance tests of memspaceHostAllPoolTest */

TEST_F(memspaceHostAllPoolTest, malloc_compliance) {
    malloc_compliance_test(pool);
}

TEST_F(memspaceHostAllPoolTest, calloc_compliance) {
    if (!umf_test::isCallocSupported(pool)) {
        GTEST_SKIP();
    }

    calloc_compliance_test(pool);
}

TEST_F(memspaceHostAllPoolTest, realloc_compliance) {
    if (!umf_test::isReallocSupported(pool)) {
        GTEST_SKIP();
    }

    realloc_compliance_test(pool);
}

TEST_F(memspaceHostAllPoolTest, free_compliance) { free_compliance_test(pool); }
