// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#ifndef UMF_MEMSPACE_HELPERS_HPP
#define UMF_MEMSPACE_HELPERS_HPP

#include "base.hpp"
#include "memspace_internal.h"
#include "memspaces/memspace_numa.h"

#include <numa.h>
#include <umf/providers/provider_os_memory.h>

#define SIZE_4K (4096UL)
#define SIZE_4M (SIZE_4K * 1024UL)

struct numaNodesTest : ::umf_test::test {
    void SetUp() override {
        ::umf_test::test::SetUp();

        if (numa_available() == -1 || numa_all_nodes_ptr == nullptr) {
            GTEST_FAIL() << "Failed to initialize libnuma";
        }

        int maxNode = numa_max_node();
        if (maxNode < 0) {
            GTEST_FAIL() << "No available numa nodes";
        }

        for (unsigned i = 0; i <= (unsigned)maxNode; i++) {
            if (numa_bitmask_isbitset(numa_all_nodes_ptr, i)) {
                nodeIds.emplace_back(i);
                maxNodeId = i;
            }
        }
    }

    std::vector<unsigned> nodeIds;
    unsigned long maxNodeId = 0;
};

struct memspaceNumaTest : ::numaNodesTest {
    void SetUp() override {
        ::numaNodesTest::SetUp();

        enum umf_result_t ret = umfMemspaceCreateFromNumaArray(
            nodeIds.data(), (unsigned)nodeIds.size(), &hMemspace);
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

struct memspaceHostAllTest : ::numaNodesTest {
    void SetUp() override {
        ::numaNodesTest::SetUp();

        hMemspace = umfMemspaceHostAllGet();
        ASSERT_NE(hMemspace, nullptr);
    }

    umf_memspace_handle_t hMemspace = nullptr;
};

struct memspaceHostAllProviderTest : ::memspaceHostAllTest {
    void SetUp() override {
        ::memspaceHostAllTest::SetUp();

        umf_result_t ret =
            umfMemoryProviderCreateFromMemspace(hMemspace, nullptr, &hProvider);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        ASSERT_NE(hProvider, nullptr);
    }

    void TearDown() override {
        ::memspaceHostAllTest::TearDown();

        umfMemoryProviderDestroy(hProvider);
    }

    umf_memory_provider_handle_t hProvider = nullptr;
};

#endif /* UMF_MEMSPACE_HELPERS_HPP */
