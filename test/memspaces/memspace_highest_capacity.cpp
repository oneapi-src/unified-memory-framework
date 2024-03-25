// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "memory_target_numa.h"
#include "memspace_helpers.hpp"
#include "memspace_internal.h"
#include "test_helpers.h"

#include <numa.h>
#include <numaif.h>
#include <umf/memspace.h>
#include <unordered_set>

using umf_test::test;

struct memspaceHighestCapacityProviderTest : ::numaNodesTest {
    void SetUp() override {
        ::numaNodesTest::SetUp();

        umf_memspace_handle_t hMemspace = umfMemspaceHighestCapacityGet();
        UT_ASSERTne(hMemspace, nullptr);

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
    int maxCapacityNode = -1;
    for (auto nodeId : nodeIds) {
        if (numa_node_size64(nodeId, nullptr) > maxCapacity) {
            maxCapacityNode = nodeId;
            maxCapacity = numa_node_size64(nodeId, nullptr);
        }
    }

    // Confirm that the HighestCapacity memspace indeed has highest capacity
    void *ptr;
    auto ret = umfMemoryProviderAlloc(hProvider, alloc_size, 0, &ptr);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    struct bitmask *nodemask = numa_allocate_nodemask();
    UT_ASSERTne(nodemask, nullptr);
    int retm = get_mempolicy(nullptr, nodemask->maskp, nodemask->size, ptr,
                             MPOL_F_ADDR);
    UT_ASSERTeq(retm, 0);
    UT_ASSERT(numa_bitmask_isbitset(nodemask, maxCapacityNode));

    ret = umfMemoryProviderFree(hProvider, ptr, alloc_size);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    numa_bitmask_free(nodemask);
}
