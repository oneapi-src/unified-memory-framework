// Copyright (C) 2023 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "memspaces/memspace_numa.h"
#include "base.hpp"
#include "memspace_helpers.hpp"
#include "memspace_internal.h"

#include <umf/providers/provider_os_memory.h>

struct memspaceNumaTest : ::numaNodesTest {
    void SetUp() override {
        ::numaNodesTest::SetUp();

        umf_result_t ret = umfMemspaceCreateFromNumaArray(
            nodeIds.data(), nodeIds.size(), &hMemspace);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        ASSERT_NE(hMemspace, nullptr);
    }

    void TearDown() override {
        ::numaNodesTest::TearDown();
        if (hMemspace) {
            umfMemspaceDestroy(hMemspace);
        }
    }

    umf_memspace_handle_t hMemspace = nullptr;
};

struct memspaceNumaProviderTest : ::memspaceNumaTest {
    void SetUp() override {
        ::memspaceNumaTest::SetUp();

        umf_result_t ret =
            umfMemoryProviderCreateFromMemspace(hMemspace, nullptr, &hProvider);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        ASSERT_NE(hProvider, nullptr);
    }

    void TearDown() override {
        ::memspaceNumaTest::TearDown();

        if (hProvider != nullptr) {
            umfMemoryProviderDestroy(hProvider);
        }
    }

    umf_memory_provider_handle_t hProvider = nullptr;
};

TEST_F(numaNodesTest, createDestroy) {
    umf_memspace_handle_t hMemspace = nullptr;
    umf_result_t ret = umfMemspaceCreateFromNumaArray(
        nodeIds.data(), nodeIds.size(), &hMemspace);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(hMemspace, nullptr);

    umfMemspaceDestroy(hMemspace);
}

TEST_F(numaNodesTest, createInvalidNullArray) {
    umf_memspace_handle_t hMemspace = nullptr;
    umf_result_t ret = umfMemspaceCreateFromNumaArray(NULL, 0, &hMemspace);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(hMemspace, nullptr);
}

TEST_F(numaNodesTest, createInvalidZeroSize) {
    umf_memspace_handle_t hMemspace = nullptr;
    umf_result_t ret =
        umfMemspaceCreateFromNumaArray(nodeIds.data(), 0, &hMemspace);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(hMemspace, nullptr);
}

TEST_F(numaNodesTest, createInvalidNullHandle) {
    umf_result_t ret =
        umfMemspaceCreateFromNumaArray(nodeIds.data(), nodeIds.size(), nullptr);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_F(memspaceNumaTest, providerFromNumaMemspace) {
    umf_memory_provider_handle_t hProvider = nullptr;
    umf_result_t ret =
        umfMemoryProviderCreateFromMemspace(hMemspace, nullptr, &hProvider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(hProvider, nullptr);

    umfMemoryProviderDestroy(hProvider);
}

TEST_F(memspaceNumaProviderTest, allocFree) {
    void *ptr = nullptr;
    size_t size = SIZE_4K;
    size_t alignment = 0;

    umf_result_t ret = umfMemoryProviderAlloc(hProvider, size, alignment, &ptr);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    memset(ptr, 0xFF, size);

    ret = umfMemoryProviderFree(hProvider, ptr, size);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
}
