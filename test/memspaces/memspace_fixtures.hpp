// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#ifndef UMF_TEST_MEMSPACE_FIXTURES_HPP
#define UMF_TEST_MEMSPACE_FIXTURES_HPP

#include <algorithm>
#include <numa.h>
#include <numaif.h>
#include <thread>

#include <umf/memspace.h>

#include "base.hpp"
#include "memspace_helpers.hpp"
#include "test_helpers.h"
#include "umf_hwloc.h"

#define SIZE_4K (4096UL)
#define SIZE_4M (SIZE_4K * 1024UL)

// In HWLOC v2.3.0, the 'hwloc_location_type_e' enum is defined inside an
// 'hwloc_location' struct. In newer versions, this enum is defined globally.
// To prevent compile errors in C++ tests related this scope change
// 'hwloc_location_type_e' has been aliased.
using hwloc_location_type_alias = decltype(hwloc_location::type);

struct numaNodesTest : ::umf_test::test {
    void SetUp() override {
        ::umf_test::test::SetUp();

        if (numa_available() == -1 || numa_all_nodes_ptr == nullptr) {
            GTEST_SKIP() << "No available NUMA support; skipped";
        }

        int maxNode = numa_max_node();
        if (maxNode < 0) {
            GTEST_FAIL() << "No available numa nodes";
        }

        for (int i = 0; i <= maxNode; i++) {
            if (numa_bitmask_isbitset(numa_all_nodes_ptr, i)) {
                nodeIds.emplace_back(i);
                maxNodeId = i;
            }
        }
    }

    std::vector<unsigned> nodeIds;
    unsigned long maxNodeId = 0;
};

using isQuerySupportedFunc = void (*)(size_t);
using memspaceGetFunc = umf_const_memspace_handle_t (*)();
using memspaceGetParams = std::tuple<isQuerySupportedFunc, memspaceGetFunc>;

struct memspaceGetTest : ::numaNodesTest,
                         ::testing::WithParamInterface<memspaceGetParams> {
    void SetUp() override {
        ::numaNodesTest::SetUp();

        if (numa_available() == -1 || numa_all_nodes_ptr == nullptr) {
            GTEST_SKIP() << "No available NUMA support; skipped";
        }

        auto [isQuerySupported, memspaceGet] = this->GetParam();
        isQuerySupported(nodeIds.front());

        if (IS_SKIPPED_OR_FAILED()) {
            return;
        }

        hMemspace = memspaceGet();
        ASSERT_NE(hMemspace, nullptr);
    }

    umf_const_memspace_handle_t hMemspace = nullptr;
};

struct memspaceProviderTest : ::memspaceGetTest {
    void SetUp() override {
        ::memspaceGetTest::SetUp();

        if (numa_available() == -1 || numa_all_nodes_ptr == nullptr) {
            GTEST_SKIP() << "No available NUMA support; skipped";
        }

        auto [isQuerySupported, memspaceGet] = ::memspaceGetTest::GetParam();
        isQuerySupported(nodeIds.front());

        // The test has been marked as skipped in isQuerySupported,
        // repeating GTEST_SKIP in fixture would only duplicate
        // the output message
        if (IS_SKIPPED_OR_FAILED()) {
            return;
        }

        umf_result_t ret =
            umfMemoryProviderCreateFromMemspace(hMemspace, nullptr, &hProvider);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        ASSERT_NE(hProvider, nullptr);
    }

    void TearDown() override {
        ::memspaceGetTest::TearDown();

        if (hProvider) {
            umfMemoryProviderDestroy(hProvider);
        }
    }

    umf_memory_provider_handle_t hProvider = nullptr;
};

struct numaNodesCapacityTest : numaNodesTest {
    void SetUp() override {
        numaNodesTest::SetUp();

        for (auto nodeId : nodeIds) {
            capacities.push_back(numa_node_size64(nodeId, nullptr));
        }
    }

    std::vector<size_t> capacities;
};

GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(memspaceGetTest);
GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(memspaceProviderTest);

TEST_P(memspaceGetTest, providerFromMemspace) {
    umf_memory_provider_handle_t hProvider = nullptr;
    umf_result_t ret =
        umfMemoryProviderCreateFromMemspace(hMemspace, nullptr, &hProvider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(hProvider, nullptr);

    umfMemoryProviderDestroy(hProvider);
}

TEST_P(memspaceProviderTest, allocFree) {
    void *ptr = nullptr;
    size_t size = SIZE_4K;
    size_t alignment = 0;

    umf_result_t ret = umfMemoryProviderAlloc(hProvider, size, alignment, &ptr);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    // Access the allocation, so that all the pages associated with it are
    // allocated on some NUMA node.
    memset(ptr, 0xFF, size);

    ret = umfMemoryProviderFree(hProvider, ptr, size);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
}

static std::vector<int> getAllCpus() {
    std::vector<int> allCpus;
    for (int i = 0; i < numa_num_possible_cpus(); ++i) {
        if (numa_bitmask_isbitset(numa_all_cpus_ptr, i)) {
            allCpus.push_back(i);
        }
    }

    return allCpus;
}

#define MAX_NODES 512

TEST_P(memspaceProviderTest, allocLocalMt) {
    auto pinAllocValidate = [&](umf_memory_provider_handle_t hProvider,
                                int cpu) {
        hwloc_topology_t topology = NULL;
        ASSERT_EQ(hwloc_topology_init(&topology), 0);
        ASSERT_EQ(hwloc_topology_load(topology), 0);

        // Pin current thread to the provided CPU.
        hwloc_cpuset_t pinCpuset = hwloc_bitmap_alloc();
        ASSERT_EQ(hwloc_bitmap_set(pinCpuset, cpu), 0);
        ASSERT_EQ(hwloc_set_cpubind(topology, pinCpuset, HWLOC_CPUBIND_THREAD),
                  0);

        // Confirm that the thread is pinned to the provided CPU.
        hwloc_cpuset_t curCpuset = hwloc_bitmap_alloc();
        ASSERT_EQ(hwloc_get_cpubind(topology, curCpuset, HWLOC_CPUBIND_THREAD),
                  0);
        ASSERT_TRUE(hwloc_bitmap_isequal(curCpuset, pinCpuset));
        hwloc_bitmap_free(curCpuset);
        hwloc_bitmap_free(pinCpuset);

        // Allocate some memory.
        const size_t size = SIZE_4K;
        const size_t alignment = 0;
        void *ptr = nullptr;

        umf_result_t ret =
            umfMemoryProviderAlloc(hProvider, size, alignment, &ptr);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        ASSERT_NE(ptr, nullptr);

        // Access the allocation, so that all the pages associated with it are
        // allocated on some NUMA node.
        memset(ptr, 0xFF, size);

        // Get the NUMA node responsible for this allocation.
        int mode = -1;
        std::vector<size_t> boundNodeIds;
        size_t allocNodeId = SIZE_MAX;
        ASSERT_NO_FATAL_FAILURE(getAllocationPolicy(ptr, maxNodeId, mode,
                                                    boundNodeIds, allocNodeId));

        // Get the CPUs associated with the specified NUMA node.
        hwloc_obj_t allocNodeObj =
            hwloc_get_obj_by_type(topology, HWLOC_OBJ_NUMANODE, allocNodeId);

        unsigned nNodes = MAX_NODES;
        std::vector<hwloc_obj_t> localNodes(MAX_NODES);
        hwloc_location loc;
        loc.location.object = allocNodeObj,
        loc.type = hwloc_location_type_alias::HWLOC_LOCATION_TYPE_OBJECT;
        ASSERT_EQ(hwloc_get_local_numanode_objs(topology, &loc, &nNodes,
                                                localNodes.data(), 0),
                  0);
        ASSERT_LE(nNodes, MAX_NODES);

        // Confirm that the allocation from this thread was made to a local
        // NUMA node.
        ASSERT_TRUE(std::any_of(localNodes.begin(), localNodes.end(),
                                [&allocNodeObj](hwloc_obj_t node) {
                                    return node == allocNodeObj;
                                }));

        ret = umfMemoryProviderFree(hProvider, ptr, size);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

        hwloc_topology_destroy(topology);
    };

    const auto cpus = getAllCpus();
    std::vector<std::thread> threads;
    for (auto cpu : cpus) {
        threads.emplace_back(pinAllocValidate, hProvider, cpu);
    }

    for (auto &thread : threads) {
        thread.join();
    }
}

#endif /* UMF_TEST_MEMSPACE_FIXTURES_HPP */
