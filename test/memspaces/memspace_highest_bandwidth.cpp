// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "memory_target_numa.h"
#include "memspace_helpers.hpp"
#include "memspace_internal.h"
#include "test_helpers.h"

#include <hwloc.h>
#include <thread>
#include <umf/memspace.h>

using umf_test::test;

// In HWLOC v2.3.0, the 'hwloc_location_type_e' enum is defined inside an
// 'hwloc_location' struct. In newer versions, this enum is defined globally.
// To prevent compile errors in C++ tests related this scope change
// 'hwloc_location_type_e' has been aliased.
using hwloc_location_type_alias = decltype(hwloc_location::type);

static bool canQueryBandwidth(size_t nodeId) {
    hwloc_topology_t topology = nullptr;
    int ret = hwloc_topology_init(&topology);
    UT_ASSERTeq(ret, 0);
    ret = hwloc_topology_load(topology);
    UT_ASSERTeq(ret, 0);

    hwloc_obj_t numaNode =
        hwloc_get_obj_by_type(topology, HWLOC_OBJ_NUMANODE, nodeId);
    UT_ASSERTne(numaNode, nullptr);

    // Setup initiator structure.
    struct hwloc_location initiator;
    initiator.location.cpuset = numaNode->cpuset;
    initiator.type = hwloc_location_type_alias::HWLOC_LOCATION_TYPE_CPUSET;

    hwloc_uint64_t value = 0;
    ret = hwloc_memattr_get_value(topology, HWLOC_MEMATTR_ID_BANDWIDTH,
                                  numaNode, &initiator, 0, &value);

    hwloc_topology_destroy(topology);
    return (ret == 0);
}

struct memspaceHighestBandwidthTest : ::numaNodesTest {
    void SetUp() override {
        ::numaNodesTest::SetUp();

        if (!canQueryBandwidth(nodeIds.front())) {
            GTEST_SKIP();
        }

        hMemspace = umfMemspaceHighestBandwidthGet();
        ASSERT_NE(hMemspace, nullptr);
    }

    umf_memspace_handle_t hMemspace = nullptr;
};

struct memspaceHighestBandwidthProviderTest : ::memspaceHighestBandwidthTest {
    void SetUp() override {
        ::memspaceHighestBandwidthTest::SetUp();

        if (!canQueryBandwidth(nodeIds.front())) {
            GTEST_SKIP();
        }

        umf_result_t ret =
            umfMemoryProviderCreateFromMemspace(hMemspace, nullptr, &hProvider);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        ASSERT_NE(hProvider, nullptr);
    }

    void TearDown() override {
        ::memspaceHighestBandwidthTest::TearDown();

        if (hProvider) {
            umfMemoryProviderDestroy(hProvider);
        }
    }

    umf_memory_provider_handle_t hProvider = nullptr;
};

TEST_F(memspaceHighestBandwidthTest, providerFromMemspace) {
    umf_memory_provider_handle_t hProvider = nullptr;
    umf_result_t ret =
        umfMemoryProviderCreateFromMemspace(hMemspace, nullptr, &hProvider);
    UT_ASSERTeq(ret, UMF_RESULT_SUCCESS);
    UT_ASSERTne(hProvider, nullptr);

    umfMemoryProviderDestroy(hProvider);
}

TEST_F(memspaceHighestBandwidthProviderTest, allocFree) {
    void *ptr = nullptr;
    size_t size = SIZE_4K;
    size_t alignment = 0;

    umf_result_t ret = umfMemoryProviderAlloc(hProvider, size, alignment, &ptr);
    UT_ASSERTeq(ret, UMF_RESULT_SUCCESS);
    UT_ASSERTne(ptr, nullptr);

    // Access the allocation, so that all the pages associated with it are
    // allocated on some NUMA node.
    memset(ptr, 0xFF, size);

    ret = umfMemoryProviderFree(hProvider, ptr, size);
    UT_ASSERTeq(ret, UMF_RESULT_SUCCESS);
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

TEST_F(memspaceHighestBandwidthProviderTest, allocLocalMt) {
    auto pinAllocValidate = [&](umf_memory_provider_handle_t hProvider,
                                int cpu) {
        hwloc_topology_t topology = NULL;
        UT_ASSERTeq(hwloc_topology_init(&topology), 0);
        UT_ASSERTeq(hwloc_topology_load(topology), 0);

        // Pin current thread to the provided CPU.
        hwloc_cpuset_t pinCpuset = hwloc_bitmap_alloc();
        UT_ASSERTeq(hwloc_bitmap_set(pinCpuset, cpu), 0);
        UT_ASSERTeq(
            hwloc_set_cpubind(topology, pinCpuset, HWLOC_CPUBIND_THREAD), 0);

        // Confirm that the thread is pinned to the provided CPU.
        hwloc_cpuset_t curCpuset = hwloc_bitmap_alloc();
        UT_ASSERTeq(
            hwloc_get_cpubind(topology, curCpuset, HWLOC_CPUBIND_THREAD), 0);
        UT_ASSERT(hwloc_bitmap_isequal(curCpuset, pinCpuset));
        hwloc_bitmap_free(curCpuset);
        hwloc_bitmap_free(pinCpuset);

        // Allocate some memory.
        const size_t size = SIZE_4K;
        const size_t alignment = 0;
        void *ptr = nullptr;

        umf_result_t ret =
            umfMemoryProviderAlloc(hProvider, size, alignment, &ptr);
        UT_ASSERTeq(ret, UMF_RESULT_SUCCESS);
        UT_ASSERTne(ptr, nullptr);

        // Access the allocation, so that all the pages associated with it are
        // allocated on some NUMA node.
        memset(ptr, 0xFF, size);

        // Get the NUMA node responsible for this allocation.
        int mode = -1;
        std::vector<size_t> boundNodeIds;
        size_t allocNodeId = SIZE_MAX;
        getAllocationPolicy(ptr, maxNodeId, mode, boundNodeIds, allocNodeId);

        // Get the CPUs associated with the specified NUMA node.
        hwloc_obj_t allocNodeObj =
            hwloc_get_obj_by_type(topology, HWLOC_OBJ_NUMANODE, allocNodeId);

        unsigned nNodes = MAX_NODES;
        std::vector<hwloc_obj_t> localNodes(MAX_NODES);
        hwloc_location loc;
        loc.location.object = allocNodeObj,
        loc.type = hwloc_location_type_alias::HWLOC_LOCATION_TYPE_OBJECT;
        UT_ASSERTeq(hwloc_get_local_numanode_objs(topology, &loc, &nNodes,
                                                  localNodes.data(), 0),
                    0);
        UT_ASSERT(nNodes <= MAX_NODES);

        // Confirm that the allocation from this thread was made to a local
        // NUMA node.
        UT_ASSERT(std::any_of(localNodes.begin(), localNodes.end(),
                              [&allocNodeObj](hwloc_obj_t node) {
                                  return node == allocNodeObj;
                              }));

        ret = umfMemoryProviderFree(hProvider, ptr, size);
        UT_ASSERTeq(ret, UMF_RESULT_SUCCESS);

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
