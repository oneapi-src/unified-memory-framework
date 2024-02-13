// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "base.hpp"

#include <numa.h>
#include <numaif.h>
#include <sched.h>

#include "test_helpers.h"
#include <umf/providers/provider_os_memory.h>

static umf_os_memory_provider_params_t UMF_OS_MEMORY_PROVIDER_PARAMS_TEST =
    umfOsMemoryProviderParamsDefault();

std::vector<int> get_available_numa_nodes_numbers() {
    if (numa_available() == -1 || numa_all_nodes_ptr == nullptr ||
        numa_num_task_nodes() <= 1) {
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

std::vector<int> get_available_cpus() {
    std::vector<int> available_cpus;
    cpu_set_t *mask = CPU_ALLOC(CPU_SETSIZE);
    CPU_ZERO(mask);

    int ret = sched_getaffinity(0, sizeof(cpu_set_t), mask);
    UT_ASSERTeq(ret, 0);
    // Get all available cpus.
    for (size_t i = 0; i < CPU_SETSIZE; ++i) {
        if (CPU_ISSET(i, mask)) {
            available_cpus.emplace_back(i);
        }
    }
    CPU_FREE(mask);

    return available_cpus;
}

void set_all_available_nodemask_bits(bitmask *nodemask) {
    UT_ASSERTne(numa_available(), -1);
    UT_ASSERTne(numa_all_nodes_ptr, nullptr);

    numa_bitmask_clearall(nodemask);

    // Set all available NUMA nodes numbers.
    copy_bitmask_to_bitmask(numa_all_nodes_ptr, nodemask);
}

struct testNuma : testing::Test {
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
        umf_result = umfMemoryProviderCreate(umfOsMemoryProviderOps(),
                                             &os_memory_provider_params,
                                             &os_memory_provider);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
        ASSERT_NE(os_memory_provider, nullptr);
    }

    int retrieve_numa_node_number(void *addr) {
        int numa_node;
        int ret = get_mempolicy(&numa_node, nullptr, 0, addr,
                                MPOL_F_NODE | MPOL_F_ADDR);
        UT_ASSERTeq(ret, 0);
        return numa_node;
    }

    struct bitmask *retrieve_nodemask(void *addr) {
        struct bitmask *retrieved_nodemask = numa_allocate_nodemask();
        UT_ASSERTne(nodemask, nullptr);
        int ret = get_mempolicy(nullptr, retrieved_nodemask->maskp,
                                nodemask->size, addr, MPOL_F_ADDR);
        UT_ASSERTeq(ret, 0);
        return retrieved_nodemask;
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

struct testNumaOnAllNodes : testNuma, testing::WithParamInterface<int> {};
struct testNumaOnAllCpus : testNuma, testing::WithParamInterface<int> {};

INSTANTIATE_TEST_SUITE_P(
    testNumaNodesAllocations, testNumaOnAllNodes,
    ::testing::ValuesIn(get_available_numa_nodes_numbers()));

INSTANTIATE_TEST_SUITE_P(testNumaNodesAllocationsAllCpus, testNumaOnAllCpus,
                         ::testing::ValuesIn(get_available_cpus()));

// Test for allocations on numa nodes. This test will be executed for all numa nodes
// available on the system. The available nodes are returned in vector from the
// get_available_numa_nodes_numbers() function and passed to test as parameters.
TEST_P(testNumaOnAllNodes, checkNumaNodesAllocations) {
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

// Test for allocations on numa nodes with mode preferred. It runs for all available
// numa nodes obtained from the get_available_numa_nodes_numbers() function.
TEST_P(testNumaOnAllNodes, checkModePreferred) {
    int numa_node_number = GetParam();
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;
    os_memory_provider_params.maxnode = numa_node_number + 1;
    numa_bitmask_setbit(nodemask, numa_node_number);
    os_memory_provider_params.nodemask = nodemask->maskp;
    os_memory_provider_params.numa_mode = UMF_NUMA_MODE_PREFERRED;
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

// Test for allocation on numa node with mode preferred and an empty nodeset.
// For the empty nodeset the memory is allocated on the node of the CPU that
// triggered the allocation. This test will be executed on all available cpus
// on which the process can run.
TEST_P(testNumaOnAllCpus, checkModePreferredEmptyNodeset) {
    int cpu = GetParam();
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;
    os_memory_provider_params.numa_mode = UMF_NUMA_MODE_PREFERRED;
    initOsProvider(os_memory_provider_params);

    umf_result_t umf_result;
    umf_result =
        umfMemoryProviderAlloc(os_memory_provider, alloc_size, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    cpu_set_t *mask = CPU_ALLOC(CPU_SETSIZE);
    CPU_ZERO(mask);

    CPU_SET(cpu, mask);
    int ret = sched_setaffinity(0, sizeof(cpu_set_t), mask);
    UT_ASSERTeq(ret, 0);

    int numa_node_number = numa_node_of_cpu(cpu);

    // This pointer must point to an initialized value before retrieving a number of
    // the numa node that the pointer was allocated on (calling get_mempolicy).
    memset(ptr, 0xFF, alloc_size);
    int retrieved_numa_node_number = retrieve_numa_node_number(ptr);
    ASSERT_EQ(retrieved_numa_node_number, numa_node_number);
    CPU_FREE(mask);
}

// Test for allocation on numa node with local mode enabled. The memory is
// allocated on the node of the CPU that triggered the allocation.
TEST_F(testNuma, checkModeLocal) {
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;
    os_memory_provider_params.numa_mode = UMF_NUMA_MODE_LOCAL;
    initOsProvider(os_memory_provider_params);

    umf_result_t umf_result;
    umf_result =
        umfMemoryProviderAlloc(os_memory_provider, alloc_size, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    int cpu = sched_getcpu();
    int numa_node_number = numa_node_of_cpu(cpu);

    // This pointer must point to an initialized value before retrieving a number of
    // the numa node that the pointer was allocated on (calling get_mempolicy).
    memset(ptr, 0xFF, alloc_size);
    int retrieved_numa_node_number = retrieve_numa_node_number(ptr);
    ASSERT_EQ(retrieved_numa_node_number, numa_node_number);
}

// Test for allocation on numa node with default mode enabled.
// Since no policy is set by the set_mempolicy function, it should
// default to the system-wide default policy, which allocates pages
// on the node of the CPU that triggers the allocation.
TEST_F(testNuma, checkModeDefault) {
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;
    initOsProvider(os_memory_provider_params);

    umf_result_t umf_result;
    umf_result =
        umfMemoryProviderAlloc(os_memory_provider, alloc_size, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    int cpu = sched_getcpu();
    int numa_node_number = numa_node_of_cpu(cpu);

    // This pointer must point to an initialized value before retrieving a number of
    // the numa node that the pointer was allocated on (calling get_mempolicy).
    memset(ptr, 0xFF, alloc_size);
    int retrieved_numa_node_number = retrieve_numa_node_number(ptr);
    ASSERT_EQ(retrieved_numa_node_number, numa_node_number);
}

// Test for allocation on numa node with default mode enabled.
// Since the bind mode is set by setmempolicy, it should fall back to it.
TEST_F(testNuma, checkModeDefaultSetMempolicy) {
    int numa_node_number = get_available_numa_nodes_numbers()[0];
    numa_bitmask_setbit(nodemask, numa_node_number);
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;
    initOsProvider(os_memory_provider_params);

    long ret = set_mempolicy(MPOL_BIND, nodemask->maskp, nodemask->size);
    ASSERT_EQ(ret, 0);

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

// Test for allocations on numa nodes with interleave mode enabled.
// The page allocations are interleaved across the set of nodes specified in nodemask.
TEST_F(testNuma, checkModeInterleave) {
    constexpr int pages_num = 1024;
    size_t page_size = sysconf(_SC_PAGE_SIZE);
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;
    os_memory_provider_params.maxnode = numa_max_node();
    set_all_available_nodemask_bits(nodemask);
    os_memory_provider_params.nodemask = nodemask->maskp;
    os_memory_provider_params.numa_mode = UMF_NUMA_MODE_INTERLEAVE;
    initOsProvider(os_memory_provider_params);

    umf_result_t umf_result;
    umf_result = umfMemoryProviderAlloc(os_memory_provider,
                                        pages_num * page_size, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    // This pointer must point to an initialized value before retrieving a number of
    // the numa node that the pointer was allocated on (calling get_mempolicy).
    memset(ptr, 0xFF, pages_num * page_size);

    // Test where each page will be allocated.
    std::vector<int> numa_nodes_numbers = get_available_numa_nodes_numbers();
    size_t index = 0;

    for (size_t i = 0; i < (size_t)pages_num; i++) {
        if (index == (size_t)numa_nodes_numbers.size()) {
            index = 0;
        }
        ASSERT_EQ(numa_nodes_numbers[index],
                  retrieve_numa_node_number((char *)ptr + page_size * i));
        index++;
    }

    bitmask *retrieved_nodemask = retrieve_nodemask(ptr);
    int ret = numa_bitmask_equal(retrieved_nodemask, nodemask);
    ASSERT_EQ(ret, 1);
    numa_bitmask_free(retrieved_nodemask);
}

// Test for allocations on a single numa node with interleave mode enabled.
TEST_F(testNuma, checkModeInterleaveSingleNode) {
    constexpr int pages_num = 1024;
    size_t page_size = sysconf(_SC_PAGE_SIZE);
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;
    os_memory_provider_params.maxnode = numa_max_node();
    std::vector<int> numa_nodes_numbers = get_available_numa_nodes_numbers();
    numa_bitmask_setbit(nodemask, numa_nodes_numbers[0]);
    os_memory_provider_params.nodemask = nodemask->maskp;
    os_memory_provider_params.numa_mode = UMF_NUMA_MODE_INTERLEAVE;
    initOsProvider(os_memory_provider_params);

    umf_result_t umf_result;
    umf_result = umfMemoryProviderAlloc(os_memory_provider,
                                        pages_num * page_size, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    // This pointer must point to an initialized value before retrieving a number of
    // the numa node that the pointer was allocated on (calling get_mempolicy).
    memset(ptr, 0xFF, pages_num * page_size);

    ASSERT_EQ(numa_nodes_numbers[0], retrieve_numa_node_number(ptr));
}

// Negative tests

// Test for allocation on numa node with local mode enabled when maxnode
// and nodemask are set. For the local mode the maxnode and nodemask must be an empty set.
TEST_F(testNuma, checkModeLocalIllegalArgSet) {
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;
    os_memory_provider_params.maxnode = numa_max_node();
    set_all_available_nodemask_bits(nodemask);
    os_memory_provider_params.nodemask = nodemask->maskp;
    os_memory_provider_params.numa_mode = UMF_NUMA_MODE_LOCAL;
    umf_result_t umf_result;
    umf_result = umfMemoryProviderCreate(umfOsMemoryProviderOps(),
                                         &os_memory_provider_params,
                                         &os_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(os_memory_provider, nullptr);
}

// Test for allocation on numa node with default mode enabled when maxnode
// and nodemask are set. For the default mode the maxnode and nodemask must be an empty set.
TEST_F(testNuma, checkModeDefaultIllegalArgSet) {
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;
    os_memory_provider_params.maxnode = numa_max_node();
    set_all_available_nodemask_bits(nodemask);
    os_memory_provider_params.nodemask = nodemask->maskp;
    umf_result_t umf_result;
    umf_result = umfMemoryProviderCreate(umfOsMemoryProviderOps(),
                                         &os_memory_provider_params,
                                         &os_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(os_memory_provider, nullptr);
}

// Test for allocation on numa node with bind mode enabled when maxnode
// and nodemask are unset. For the bind mode the maxnode and nodemask
// must be a non-empty set.
TEST_F(testNuma, checkModeBindIllegalArgSet) {
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;
    os_memory_provider_params.numa_mode = UMF_NUMA_MODE_BIND;
    umf_result_t umf_result;
    umf_result = umfMemoryProviderCreate(umfOsMemoryProviderOps(),
                                         &os_memory_provider_params,
                                         &os_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(os_memory_provider, nullptr);
}

// Test for allocation on numa node with interleave mode enabled when maxnode
// and nodemask are unset. For the interleve mode the maxnode and nodemask
// must be a non-empty set.
TEST_F(testNuma, checkModeInterleaveIllegalArgSet) {
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;
    os_memory_provider_params.numa_mode = UMF_NUMA_MODE_INTERLEAVE;
    umf_result_t umf_result;
    umf_result = umfMemoryProviderCreate(umfOsMemoryProviderOps(),
                                         &os_memory_provider_params,
                                         &os_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(os_memory_provider, nullptr);
}
