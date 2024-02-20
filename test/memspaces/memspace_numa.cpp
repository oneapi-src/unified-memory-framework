// Copyright (C) 2023 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "base.hpp"

#include "memspace_internal.h"
#include "memspaces/memspace_numa.h"

#include <umf/providers/provider_os_memory.h>

#include <numa.h>

#define SIZE_4K (4096)

struct numa_nodes_test : ::umf_test::test {
    void SetUp() override {
        ::umf_test::test::SetUp();

        if (numa_available() == -1) {
            GTEST_SKIP() << "Failed to initialize libnuma";
        }

        int numNodes = numa_max_node();
        if (numNodes < 0) {
            GTEST_SKIP() << "No available numa nodes";
        }

        for (int i = 0; i <= numNodes; i++) {
            nodeIds.emplace_back(i);
        }
    }

    std::vector<size_t> nodeIds;
};

struct numa_memspace_test : ::numa_nodes_test {
    void SetUp() override {
        ::numa_nodes_test::SetUp();
        if (nodeIds.size()) {
            enum umf_result_t ret = umfMemspaceCreateFromNumaArray(
                nodeIds.data(), nodeIds.size(), &memspace);
            ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
            ASSERT_NE(memspace, nullptr);
        }
    }

    void TearDown() override {
        ::numa_nodes_test::TearDown();
        if (memspace) {
            umfMemspaceDestroy(memspace);
        }
    }

    umf_memspace_handle_t memspace = nullptr;
};

struct numa_memspace_provider_test : ::numa_memspace_test {
    void SetUp() override {
        ::numa_memspace_test::SetUp();
        if (nodeIds.size()) {
            umf_result_t ret = umfMemoryProviderCreateFromMemspace(
                memspace, nullptr, &provider);
            ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
            ASSERT_NE(provider, nullptr);
        }
    }

    void TearDown() override {
        ::numa_memspace_test::TearDown();
        if (provider) {
            umfMemoryProviderDestroy(provider);
        }
    }

    umf_memory_provider_handle_t provider = nullptr;
};

TEST_F(numa_nodes_test, create_destroy) {
    umf_memspace_handle_t hMemspace = nullptr;
    enum umf_result_t ret = umfMemspaceCreateFromNumaArray(
        nodeIds.data(), nodeIds.size(), &hMemspace);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(hMemspace, nullptr);

    umfMemspaceDestroy(hMemspace);
}

TEST_F(numa_nodes_test, create_null_array) {
    umf_memspace_handle_t hMemspace = nullptr;
    enum umf_result_t ret = umfMemspaceCreateFromNumaArray(NULL, 0, &hMemspace);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(hMemspace, nullptr);
}

TEST_F(numa_nodes_test, create_zero_size) {
    umf_memspace_handle_t hMemspace = nullptr;
    enum umf_result_t ret =
        umfMemspaceCreateFromNumaArray(nodeIds.data(), 0, &hMemspace);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(hMemspace, nullptr);
}

TEST_F(numa_nodes_test, create_null_handle) {
    enum umf_result_t ret =
        umfMemspaceCreateFromNumaArray(nodeIds.data(), nodeIds.size(), nullptr);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_F(numa_memspace_test, provider_from_numa_memspace) {
    umf_memory_provider_handle_t provider = nullptr;
    enum umf_result_t ret =
        umfMemoryProviderCreateFromMemspace(memspace, nullptr, &provider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    umfMemoryProviderDestroy(provider);
}

TEST_F(numa_memspace_provider_test, alloc_free) {
    void *ptr = nullptr;
    size_t size = SIZE_4K;
    size_t alignment = 0;

    enum umf_result_t ret =
        umfMemoryProviderAlloc(provider, size, alignment, &ptr);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    memset(ptr, 0xFF, size);

    ret = umfMemoryProviderFree(provider, ptr, size);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
}
