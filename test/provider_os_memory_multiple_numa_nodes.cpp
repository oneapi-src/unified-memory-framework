// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "base.hpp"

#include <numa.h>
#include <numaif.h>

#include <umf/providers/provider_os_memory.h>

static umf_os_memory_provider_params_t UMF_OS_MEMORY_PROVIDER_PARAMS_TEST =
    umfOsMemoryProviderParamsDefault();

std::vector<int> get_available_numa_nodes_numbers() {
    if (numa_available() == -1 || numa_all_nodes_ptr == nullptr) {
        return {-1};
    }

    std::vector<int> available_numa_nodes_numbers;
    // Get all available NUMA nodes numbers.
    for (size_t i = 0; i < (size_t)numa_max_node() + 1; ++i) {
        if (numa_bitmask_isbitset(numa_all_nodes_ptr, i) == 1) {
            available_numa_nodes_numbers.emplace_back(i);
        }
    }

    return available_numa_nodes_numbers;
}

struct testNumaNodes : public testing::TestWithParam<int> {
    void SetUp() override {
        if (numa_available() == -1) {
            GTEST_SKIP() << "Test skipped, NUMA not available";
        }
        if (numa_num_task_nodes() <= 1) {
            GTEST_SKIP()
                << "Test skipped, the number of NUMA nodes is less than two";
        }

        nodemask = numa_allocate_nodemask();
        ASSERT_NE(nodemask, nullptr);
    }

    void
    initOsProvider(umf_os_memory_provider_params_t os_memory_provider_params) {
        umf_result_t umf_result;
        umf_result = umfMemoryProviderCreate(&UMF_OS_MEMORY_PROVIDER_OPS,
                                             &os_memory_provider_params,
                                             &os_memory_provider);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        ASSERT_NE(os_memory_provider, nullptr);
    }

    int retrieve_numa_node_number(void *addr) {
        int numa_node;
        int ret = get_mempolicy(&numa_node, nullptr, 0, addr,
                                MPOL_F_NODE | MPOL_F_ADDR);
        EXPECT_EQ(ret, 0);
        return numa_node;
    }

    void TearDown() override {
        umf_result_t umf_result;
        if (ptr) {
            umf_result =
                umfMemoryProviderFree(os_memory_provider, ptr, alloc_size);
            ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        }
        if (os_memory_provider) {
            umfMemoryProviderDestroy(os_memory_provider);
        }
        if (nodemask) {
            numa_bitmask_clearall(nodemask);
            numa_bitmask_free(nodemask);
        }
    }

    size_t alloc_size = 1024;
    void *ptr = nullptr;
    bitmask *nodemask = nullptr;
    umf_memory_provider_handle_t os_memory_provider = nullptr;
};

INSTANTIATE_TEST_SUITE_P(
    testNumaNodesAllocations, testNumaNodes,
    ::testing::ValuesIn(get_available_numa_nodes_numbers()));

// Test for allocations on numa nodes. This test will be executed for all numa nodes
// available on the system. The available nodes are returned in vector from the
// get_available_numa_nodes_numbers() function and passed to test as parameters.
TEST_P(testNumaNodes, checkNumaNodesAllocations) {
    int numa_node_number = GetParam();
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;
    os_memory_provider_params.maxnode = numa_node_number + 1;
    numa_bitmask_setbit(nodemask, numa_node_number);
    os_memory_provider_params.nodemask = nodemask->maskp;
    os_memory_provider_params.numa_mode = UMF_NUMA_MODE_BIND;
    initOsProvider(os_memory_provider_params);

    umf_result_t umf_result;
    umf_result =
        umfMemoryProviderAlloc(os_memory_provider, alloc_size, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    // This pointer must point to an initialized value before retrieving a number of
    // the numa node that the pointer was allocated on (calling get_mempolicy).
    memset(ptr, 0xFF, alloc_size);
    int retrieved_numa_node_number = retrieve_numa_node_number(ptr);
    ASSERT_EQ(retrieved_numa_node_number, numa_node_number);
}
