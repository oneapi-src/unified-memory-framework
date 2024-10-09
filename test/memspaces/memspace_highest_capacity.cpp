// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "memspace_fixtures.hpp"
#include "memspace_helpers.hpp"
#include "memspace_internal.h"
#include "memtarget_numa.h"
#include "numa_helpers.hpp"
#include "test_helpers.h"

#include <numa.h>
#include <numaif.h>
#include <umf/memspace.h>
#include <unordered_set>

using umf_test::test;

struct memspaceHighestCapacityProviderTest : ::numaNodesTest {
    void SetUp() override {
        ::numaNodesTest::SetUp();

        umf_const_memspace_handle_t hMemspace = umfMemspaceHighestCapacityGet();
        ASSERT_NE(hMemspace, nullptr);

        umf_result_t ret =
            umfMemoryProviderCreateFromMemspace(hMemspace, nullptr, &hProvider);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        ASSERT_NE(hProvider, nullptr);
    }

    void TearDown() override {
        ::numaNodesTest::TearDown();
        umfMemoryProviderDestroy(hProvider);
    }

    umf_memory_provider_handle_t hProvider = nullptr;
};

TEST_F(memspaceHighestCapacityProviderTest, highestCapacityVerify) {
    static constexpr size_t alloc_size = 1024;

    long long maxCapacity = 0;
    std::vector<int> maxCapacityNodes{};
    for (auto nodeId : nodeIds) {
        if (numa_node_size64(nodeId, nullptr) > maxCapacity) {
            maxCapacity = numa_node_size64(nodeId, nullptr);
        }
    }

    for (auto nodeId : nodeIds) {
        if (numa_node_size64(nodeId, nullptr) == maxCapacity) {
            maxCapacityNodes.push_back(nodeId);
        }
    }

    // Confirm that the HighestCapacity memspace indeed has highest capacity
    void *ptr;
    auto ret = umfMemoryProviderAlloc(hProvider, alloc_size, 0, &ptr);
    memset(ptr, 0, alloc_size);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    int nodeId = -1;
    ASSERT_NO_FATAL_FAILURE(getNumaNodeByPtr(ptr, &nodeId));

    ASSERT_TRUE(std::any_of(maxCapacityNodes.begin(), maxCapacityNodes.end(),
                            [nodeId](int node) { return nodeId == node; }));

    ret = umfMemoryProviderFree(hProvider, ptr, alloc_size);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
}
