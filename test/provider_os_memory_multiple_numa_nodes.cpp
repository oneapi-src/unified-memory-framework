// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "base.hpp"
#include "numa_helpers.hpp"
#include "test_helpers.h"

#include <algorithm>
#include <numa.h>
#include <numaif.h>
#include <random>
#include <sched.h>

#include <umf/providers/provider_os_memory.h>

static umf_os_memory_provider_params_t UMF_OS_MEMORY_PROVIDER_PARAMS_TEST =
    umfOsMemoryProviderParamsDefault();

std::vector<unsigned> get_available_numa_nodes() {
    if (numa_available() == -1 || numa_all_nodes_ptr == nullptr) {
        return std::vector<unsigned>();
    }

    std::vector<unsigned> available_numa_nodes;
    // Get all available NUMA nodes numbers.
    printf("All NUMA nodes: ");
    for (size_t i = 0; i < (size_t)numa_max_node() + 1; ++i) {
        if (numa_bitmask_isbitset(numa_all_nodes_ptr, i) == 1) {
            available_numa_nodes.emplace_back((unsigned)i);
            printf("%ld, ", i);
        }
    }
    printf("\n");

    return available_numa_nodes;
}

std::vector<int> get_available_cpus() {
    std::vector<int> available_cpus;
    cpu_set_t *mask = CPU_ALLOC(CPU_SETSIZE);
    CPU_ZERO(mask);

    int ret = sched_getaffinity(0, sizeof(cpu_set_t), mask);

    if (ret != 0) {
        available_cpus.emplace_back(-1);
        CPU_FREE(mask);

        return available_cpus;
    }

    // Get all available cpus.
    printf("All CPUs: ");
    for (size_t i = 0; i < CPU_SETSIZE; ++i) {
        if (CPU_ISSET(i, mask)) {
            available_cpus.emplace_back(i);
            printf("%ld, ", i);
        }
    }
    printf("\n");
    CPU_FREE(mask);

    return available_cpus;
}

void set_all_available_nodemask_bits(bitmask *nodemask) {
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

    void retrieve_nodemask(void *addr, bitmask **retrieved_nodemask) {
        *retrieved_nodemask = numa_allocate_nodemask();

        ASSERT_NE(nodemask, nullptr);
        ASSERT_NE(*retrieved_nodemask, nullptr);

        int ret = get_mempolicy(nullptr, (*retrieved_nodemask)->maskp,
                                nodemask->size, addr, MPOL_F_ADDR);

        ASSERT_EQ(ret, 0);
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

struct testNumaOnEachNode : testNuma, testing::WithParamInterface<unsigned> {};

/*
 - In case of the lack of support for NUMA on the system
 get_available_numa_nodes() returns an empty vector<unsigned>
 - Then in INSTANTIATE_TEST_SUITE_P an empty container is passed as the 3rd arg
 (param_generator)
 - Therefore INSTANTIATE_TEST_SUITE_P expands to nothing, which causes the test
 to fail in the test suite GoogleTestVerification
- GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(testNumaOnEachNode) allows the
test suite testNumaOnEachNode to be uninstantiated, suppressing
the test failure
- Additionally, the fixture testNumaOnEachNode uses SetUp from testNuma before
running every test, thus the test is eventually skipped when the lack of NUMA
support is determined by numa_available()
- (Therefore probably a vector with dummy values could be returned instead of
using the macro)
*/
GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(testNumaOnEachNode);

INSTANTIATE_TEST_SUITE_P(testNumaNodesAllocations, testNumaOnEachNode,
                         ::testing::ValuesIn(get_available_numa_nodes()));

// Test for allocations on numa nodes. It will be executed on each of
// the available numa nodes.
TEST_P(testNumaOnEachNode, checkNumaNodesAllocations) {
    unsigned numa_node_number = GetParam();
    ASSERT_GE(numa_node_number, 0);

    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;

    os_memory_provider_params.numa_list = &numa_node_number;
    os_memory_provider_params.numa_list_len = 1;
    os_memory_provider_params.numa_mode = UMF_NUMA_MODE_BIND;
    initOsProvider(os_memory_provider_params);

    umf_result_t umf_result;
    umf_result =
        umfMemoryProviderAlloc(os_memory_provider, alloc_size, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    // 'ptr' must point to an initialized value before retrieving its numa node
    memset(ptr, 0xFF, alloc_size);
    EXPECT_NODE_EQ(ptr, numa_node_number);
}

// Test for allocations on numa nodes with mode preferred. It will be executed
// on each of the available numa nodes.
TEST_P(testNumaOnEachNode, checkModePreferred) {
    unsigned numa_node_number = GetParam();
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;

    os_memory_provider_params.numa_list = &numa_node_number;
    numa_bitmask_setbit(nodemask, numa_node_number);
    os_memory_provider_params.numa_list_len = 1;
    os_memory_provider_params.numa_mode = UMF_NUMA_MODE_PREFERRED;
    initOsProvider(os_memory_provider_params);

    umf_result_t umf_result;
    umf_result =
        umfMemoryProviderAlloc(os_memory_provider, alloc_size, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    // 'ptr' must point to an initialized value before retrieving its numa node
    memset(ptr, 0xFF, alloc_size);
    EXPECT_NODE_EQ(ptr, numa_node_number);
}

// Test for allocation on numa node with default mode enabled.
// We explicitly set the bind mode (via set_mempolicy) so it should fall back to it.
// It will be executed on each of the available numa nodes.
TEST_P(testNumaOnEachNode, checkModeDefaultSetMempolicy) {
    unsigned numa_node_number = GetParam();
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

    // 'ptr' must point to an initialized value before retrieving its numa node
    memset(ptr, 0xFF, alloc_size);
    EXPECT_NODE_EQ(ptr, numa_node_number);
}

// Test for allocations on a single numa node with interleave mode enabled.
// It will be executed on each of the available numa nodes.
TEST_P(testNumaOnEachNode, checkModeInterleaveSingleNode) {
    unsigned numa_node_number = GetParam();

    constexpr int pages_num = 1024;
    size_t page_size = sysconf(_SC_PAGE_SIZE);
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;

    os_memory_provider_params.numa_list = &numa_node_number;
    os_memory_provider_params.numa_list_len = 1;
    os_memory_provider_params.numa_mode = UMF_NUMA_MODE_INTERLEAVE;
    initOsProvider(os_memory_provider_params);

    umf_result_t umf_result;
    umf_result = umfMemoryProviderAlloc(os_memory_provider,
                                        pages_num * page_size, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    // 'ptr' must point to an initialized value before retrieving its numa node
    memset(ptr, 0xFF, pages_num * page_size);
    EXPECT_NODE_EQ(ptr, numa_node_number);
}

struct testNumaOnEachCpu : testNuma, testing::WithParamInterface<int> {
    void SetUp() override {
        ::testNuma::SetUp();

        int cpuNumber = this->GetParam();

        if (cpuNumber < 0) {
            GTEST_FAIL() << "get_available_cpus() error";
        }
    }
};

INSTANTIATE_TEST_SUITE_P(testNumaNodesAllocationsAllCpus, testNumaOnEachCpu,
                         ::testing::ValuesIn(get_available_cpus()));

// Test for allocation on numa node with mode preferred and an empty nodeset.
// For the empty nodeset the memory is allocated on the node of the CPU that
// triggered the allocation. It will be executed on each available CPU.
TEST_P(testNumaOnEachCpu, checkModePreferredEmptyNodeset) {
    int cpu = GetParam();
    ASSERT_GE(cpu, 0);

    cpu_set_t *mask = CPU_ALLOC(CPU_SETSIZE);
    CPU_ZERO(mask);

    CPU_SET(cpu, mask);
    int ret = sched_setaffinity(0, sizeof(cpu_set_t), mask);
    CPU_FREE(mask);

    ASSERT_EQ(ret, 0);

    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;
    os_memory_provider_params.numa_mode = UMF_NUMA_MODE_PREFERRED;
    initOsProvider(os_memory_provider_params);

    umf_result_t umf_result;
    umf_result =
        umfMemoryProviderAlloc(os_memory_provider, alloc_size, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    // Verify we're on the expected CPU
    int cpu_check = sched_getcpu();
    ASSERT_EQ(cpu, cpu_check);

    int numa_node_number = numa_node_of_cpu(cpu);
    printf("Got CPU: %d, got numa node: %d\n", cpu, numa_node_number);

    // 'ptr' must point to an initialized value before retrieving its numa node
    memset(ptr, 0xFF, alloc_size);
    EXPECT_NODE_EQ(ptr, numa_node_number);
}

// Test for allocation on numa node with local mode enabled. The memory is
// allocated on the node of the CPU that triggered the allocation.
// It will be executed on each available CPU.
TEST_P(testNumaOnEachCpu, checkModeLocal) {
    int cpu = GetParam();
    cpu_set_t *mask = CPU_ALLOC(CPU_SETSIZE);
    CPU_ZERO(mask);

    CPU_SET(cpu, mask);
    int ret = sched_setaffinity(0, sizeof(cpu_set_t), mask);
    CPU_FREE(mask);

    ASSERT_EQ(ret, 0);

    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;
    os_memory_provider_params.numa_mode = UMF_NUMA_MODE_LOCAL;
    initOsProvider(os_memory_provider_params);

    umf_result_t umf_result;
    umf_result =
        umfMemoryProviderAlloc(os_memory_provider, alloc_size, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    // Verify we're on the expected CPU
    int cpu_check = sched_getcpu();
    ASSERT_EQ(cpu, cpu_check);

    int numa_node_number = numa_node_of_cpu(cpu);
    printf("Got CPU: %d, got numa node: %d\n", cpu, numa_node_number);

    // 'ptr' must point to an initialized value before retrieving its numa node
    memset(ptr, 0xFF, alloc_size);
    EXPECT_NODE_EQ(ptr, numa_node_number);
}

// Test for allocation on numa node with default mode enabled.
// Since no policy is set (via set_mempolicy) it should default to the system-wide
// default policy - it allocates pages on the node of the CPU that triggered
// the allocation.
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
    printf("Got CPU: %d, got numa node: %d\n", cpu, numa_node_number);

    // 'ptr' must point to an initialized value before retrieving its numa node
    memset(ptr, 0xFF, alloc_size);
    EXPECT_NODE_EQ(ptr, numa_node_number);
}

// Test for allocations on numa nodes with interleave mode enabled.
// The page allocations are interleaved across the set of all available nodes.
TEST_F(testNuma, checkModeInterleave) {
    constexpr int pages_num = 1024;
    size_t page_size = sysconf(_SC_PAGE_SIZE);
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;

    std::vector<unsigned> numa_nodes = get_available_numa_nodes();
    set_all_available_nodemask_bits(nodemask);

    os_memory_provider_params.numa_list = numa_nodes.data();
    os_memory_provider_params.numa_list_len = numa_nodes.size();
    os_memory_provider_params.numa_mode = UMF_NUMA_MODE_INTERLEAVE;
    initOsProvider(os_memory_provider_params);

    umf_result_t umf_result;
    umf_result = umfMemoryProviderAlloc(os_memory_provider,
                                        pages_num * page_size, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    // 'ptr' must point to an initialized value before retrieving its numa node
    memset(ptr, 0xFF, pages_num * page_size);

    // Test where each page will be allocated.
    // Get the first numa node for ptr; Each next page is expected to be on next nodes.
    int node = -1;
    ASSERT_NO_FATAL_FAILURE(getNumaNodeByPtr(ptr, &node));
    ASSERT_GE(node, 0);
    int index = -1;
    for (size_t i = 0; i < numa_nodes.size(); i++) {
        if (numa_nodes[i] == (unsigned)node) {
            index = i;
            break;
        }
    }
    ASSERT_GE(index, 0);
    ASSERT_LT(index, numa_nodes.size());

    for (size_t i = 1; i < (size_t)pages_num; i++) {
        index = (index + 1) % numa_nodes.size();
        EXPECT_NODE_EQ((char *)ptr + page_size * i, numa_nodes[index]);
    }

    bitmask *retrieved_nodemask = nullptr;
    retrieve_nodemask(ptr, &retrieved_nodemask);

    if (IS_SKIPPED_OR_FAILED()) {
        return;
    }

    int ret = numa_bitmask_equal(retrieved_nodemask, nodemask);
    numa_bitmask_free(retrieved_nodemask);

    EXPECT_EQ(ret, 1);
}

// Test for allocations on numa nodes with interleave mode enabled and custom part size set.
// The page allocations are interleaved across the set of nodes specified in nodemask.
TEST_F(testNuma, checkModeInterleaveCustomPartSize) {
    constexpr int part_num = 1024;
    long _page_size = sysconf(_SC_PAGE_SIZE);
    ASSERT_GT(_page_size, 0);
    size_t page_size = _page_size;
    size_t part_size = page_size * 100;
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;

    std::vector<unsigned> numa_nodes = get_available_numa_nodes();

    os_memory_provider_params.numa_list = numa_nodes.data();
    os_memory_provider_params.numa_list_len = numa_nodes.size();
    os_memory_provider_params.numa_mode = UMF_NUMA_MODE_INTERLEAVE;
    // part size do not need to be multiple of page size
    os_memory_provider_params.part_size = part_size - 1;
    initOsProvider(os_memory_provider_params);

    size_t size = part_num * part_size;
    umf_result_t umf_result;
    umf_result = umfMemoryProviderAlloc(os_memory_provider, size, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    // 'ptr' must point to an initialized value before retrieving its numa node
    memset(ptr, 0xFF, size);
    // Test where each page will be allocated.
    // Get the first numa node for ptr; Each next part is expected to be on next nodes.
    int node = -1;
    ASSERT_NO_FATAL_FAILURE(getNumaNodeByPtr(ptr, &node));
    ASSERT_GE(node, 0);
    int index = -1;
    for (size_t i = 0; i < numa_nodes.size(); i++) {
        if (numa_nodes[i] == (unsigned)node) {
            index = i;
            break;
        }
    }
    ASSERT_GE(index, 0);
    ASSERT_LT(index, numa_nodes.size());

    for (size_t i = 0; i < (size_t)part_num; i++) {
        for (size_t j = 0; j < part_size; j += page_size) {
            ASSERT_NODE_EQ((char *)ptr + part_size * i + j, numa_nodes[index]);
        }
        index = (index + 1) % numa_nodes.size();
    }
    umfMemoryProviderFree(os_memory_provider, ptr, size);

    // test allocation smaller then part size
    size = part_size / 2 + 1;
    umf_result = umfMemoryProviderAlloc(os_memory_provider, size, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);
    memset(ptr, 0xFF, size);
    EXPECT_NODE_EQ(ptr, numa_nodes[index]);
    umfMemoryProviderFree(os_memory_provider, ptr, size);
}

using numaSplitOut = std::vector<std::vector<unsigned>>;

// Input for Numa split test - in the following format
// <numa nodes required, number of pages to allocate, input partitions, expected bind of pages >
using numaSplitArg =
    std::tuple<unsigned, size_t, std::vector<umf_numa_split_partition_t>,
               numaSplitOut>;

numaSplitOut mergeOutVec(std::initializer_list<numaSplitOut> vecs) {
    size_t size = 0;
    for (numaSplitOut v : vecs) {
        size += v.size();
    }
    numaSplitOut ret;
    ret.reserve(size);
    for (numaSplitOut v : vecs) {
        ret.insert(ret.end(), v.begin(), v.end());
    }
    return ret;
}

struct testNumaSplit : testNuma, testing::WithParamInterface<numaSplitArg> {
    static std::vector<numaSplitArg> getTestInput() {
        std::vector<numaSplitArg> ret;
        std::vector<umf_numa_split_partition_t> in = {{2, 0},  {4, 1}, {1, 2},
                                                      {10, 1}, {1, 2}, {17, 0}};
        auto out = mergeOutVec({numaSplitOut(2, {0}),
                                numaSplitOut(4, {1}),
                                {{2}},
                                numaSplitOut(10, {1}),
                                {{2}},
                                numaSplitOut(17, {0})});

        ret.push_back({3, 35, in, out});

        out = mergeOutVec({{{0}, {0, 1}},
                           numaSplitOut(3, {1}),
                           {{1, 2}, {1, 2}},
                           numaSplitOut(8, {1}),
                           {{0, 1, 2}},
                           numaSplitOut(15, {0})});

        ret.push_back({3, 31, in, out});

        in = {{31, 1}, {17, 1}, {14, 2}, {19, 0}, {8, 2}, {5, 1}, {15, 2}};
        out = mergeOutVec({
            numaSplitOut(28, {1}),
            {{1, 2}},
            numaSplitOut(7, {2}),
            {{0, 2}},
            numaSplitOut(11, {0}),
            {{0, 2}},
            numaSplitOut(4, {2}),
            {{1, 2}},
            numaSplitOut(2, {1}),
            {{1, 2}},
            numaSplitOut(8, {2}),
        });

        ret.push_back({3, 65, in, out});

        out = {{0, 1, 2}};
        ret.push_back({3, 1, in, out});

        out = {{1}, {0, 1, 2}, {0, 1, 2}};
        ret.push_back({3, 3, in, out});

        in = {{1, 0}, {1, 2}};
        out = {{0}, {2}};
        ret.push_back({3, 2, in, out});

        in = {{1, 0}, {UINT32_MAX, 1}};
        out = {{0, 1}, {1}};
        ret.push_back({3, 2, in, out});

        in = {};
        out = {{0}, {0, 1}, {1}, {1, 2}, {2}};
        ret.push_back({3, 5, in, out});
        out = {{0}, {0}, {0, 1}, {1}, {1}};
        ret.push_back({2, 5, in, out});

        std::vector<unsigned> numa_nodes = get_available_numa_nodes();

        std::vector<umf_numa_split_partition_t> in1, in2, in3;

        for (unsigned i = 0; i < numa_nodes.size(); i++) {
            numaSplitOut out1, out2, out3;
            std::vector<umf_numa_split_partition_t> in1, in2, in3;
            in1 = {};
            out1 = {{}};
            for (unsigned j = 0; j <= i; j++) {
                in2.push_back({42, j});
                in3.push_back({j + 1, j});
                out1[0].push_back(j);
                out2.push_back({j});
                out3 = mergeOutVec({out3, numaSplitOut(j + 1, {j})});
            }
            unsigned z = i + 1;
            ret.push_back({z, 1, in1, out1});
            ret.push_back({z, z, in2, out2});
            ret.push_back({z, z * (z - 1) / 2 + z, in3, out3});
        }
        return ret;
    }
};

INSTANTIATE_TEST_SUITE_P(checkModeSplit, testNumaSplit,
                         ::testing::ValuesIn(testNumaSplit::getTestInput()));

// positive test for numa mode split
TEST_P(testNumaSplit, checkModeSplit) {
    auto &param = GetParam();
    long _page_size = sysconf(_SC_PAGE_SIZE);
    ASSERT_GT(_page_size, 0);
    size_t page_size = _page_size;
    auto [required_numa_nodes, pages, in, out] = param;

    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;

    std::vector<unsigned> numa_nodes = get_available_numa_nodes();

    if (numa_nodes.size() < required_numa_nodes) {
        GTEST_SKIP_("Not enough numa nodes");
    }

    ASSERT_EQ(out.size(), pages)
        << "Wrong test input - out array size doesn't match page count";

    // If input partitions are not defined then partitions are created based on numa_list order.
    // Do not shuffle them in this case, as this test require deterministic binds
    if (in.size() != 0) {
        std::mt19937 g(0);
        std::shuffle(numa_nodes.begin(),
                     numa_nodes.begin() + required_numa_nodes, g);
    }

    os_memory_provider_params.numa_list = numa_nodes.data();
    os_memory_provider_params.numa_list_len = required_numa_nodes;
    os_memory_provider_params.numa_mode = UMF_NUMA_MODE_SPLIT;

    os_memory_provider_params.partitions = in.data();
    os_memory_provider_params.partitions_len = in.size();
    initOsProvider(os_memory_provider_params);

    size_t size = page_size * pages;
    umf_result_t umf_result;
    umf_result = umfMemoryProviderAlloc(os_memory_provider, size, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    struct bitmask *nodemask = numa_allocate_nodemask();

    // 'ptr' must point to an initialized value before retrieving its numa node
    memset(ptr, 0xFF, size);
    // Test where each page will be allocated.
    size_t index = 0;
    for (const auto &x : out) {
        numa_bitmask_clearall(nodemask);

        // Query the memory policy for the specific address
        get_mempolicy(NULL, nodemask->maskp, nodemask->size,
                      (char *)ptr + page_size * index++, MPOL_F_ADDR);

        std::vector<unsigned> bindNodes;
        for (unsigned i = 0; i < nodemask->size; i++) {
            if (numa_bitmask_isbitset(nodemask, i)) {
                bindNodes.push_back(i);
            }
        }

        EXPECT_EQ(x, bindNodes) << "index:" << index - 1;
    }
    numa_free_nodemask(nodemask);
    umfMemoryProviderFree(os_memory_provider, ptr, size);
}

// Test for allocations on all numa nodes with BIND mode.
// According to mbind it should go to the closest node.
TEST_F(testNuma, checkModeBindOnAllNodes) {
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;

    std::vector<unsigned> numa_nodes = get_available_numa_nodes();

    os_memory_provider_params.numa_list = numa_nodes.data();
    os_memory_provider_params.numa_list_len = numa_nodes.size();
    os_memory_provider_params.numa_mode = UMF_NUMA_MODE_BIND;
    initOsProvider(os_memory_provider_params);

    umf_result_t umf_result;
    umf_result =
        umfMemoryProviderAlloc(os_memory_provider, alloc_size, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    // 'ptr' must point to an initialized value before retrieving its numa node
    memset(ptr, 0xFF, alloc_size);

    int node = -1;
    ASSERT_NO_FATAL_FAILURE(getNumaNodeByPtr(ptr, &node));
    unsigned retrieved_numa_node_number = (unsigned)node;

    int read_cpu = sched_getcpu();
    int read_numa_node = numa_node_of_cpu(read_cpu);
    printf("Got CPU: %d, got numa node: %d\n", read_cpu, read_numa_node);

    // Verify if numa node related to CPU triggering allocation is in the original list
    size_t count = 0;
    for (size_t i = 0; i < numa_nodes.size(); i++) {
        if (retrieved_numa_node_number == numa_nodes[i]) {
            count++;
        }
    }
    EXPECT_EQ(count, 1);
    // ... and it's the one which we expect
    EXPECT_EQ(retrieved_numa_node_number, read_numa_node);
}

// Negative tests for policies with illegal arguments.

// Local mode enabled when numa_list is set.
// For the local mode the nodeset must be empty.
TEST_F(testNuma, checkModeLocalIllegalArgSet) {
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;

    std::vector<unsigned> numa_nodes = get_available_numa_nodes();

    os_memory_provider_params.numa_list = numa_nodes.data();
    os_memory_provider_params.numa_list_len = numa_nodes.size();
    os_memory_provider_params.numa_mode = UMF_NUMA_MODE_LOCAL;

    umf_result_t umf_result;
    umf_result = umfMemoryProviderCreate(umfOsMemoryProviderOps(),
                                         &os_memory_provider_params,
                                         &os_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(os_memory_provider, nullptr);
}

// Default mode enabled when numa_list is set.
// For the default mode the nodeset must be empty.
TEST_F(testNuma, checkModeDefaultIllegalArgSet) {
    umf_os_memory_provider_params_t os_memory_provider_params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_TEST;

    std::vector<unsigned> numa_nodes = get_available_numa_nodes();

    os_memory_provider_params.numa_list = numa_nodes.data();
    os_memory_provider_params.numa_list_len = numa_nodes.size();

    umf_result_t umf_result;
    umf_result = umfMemoryProviderCreate(umfOsMemoryProviderOps(),
                                         &os_memory_provider_params,
                                         &os_memory_provider);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(os_memory_provider, nullptr);
}

// Bind mode enabled when numa_list is not set.
// For the bind mode the nodeset must be non-empty.
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

// Interleave mode enabled numa_list is not set.
// For the interleave mode the nodeset must be non-empty.
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
