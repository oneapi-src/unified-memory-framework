// Copyright (C) 2024-2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <umf/memspace.h>

#include "memspace_fixtures.hpp"
#include "memspace_helpers.hpp"
#include "memspace_internal.h"
#include "numa_helpers.hpp"
#include "test_helpers.h"

static void canQueryBandwidth(size_t nodeId) {
    hwloc_topology_t topology = nullptr;
    int ret = hwloc_topology_init(&topology);
    ASSERT_EQ(ret, 0);

    ret = hwloc_topology_load(topology);
    ASSERT_EQ(ret, 0);

    hwloc_obj_t numaNode =
        hwloc_get_obj_by_type(topology, HWLOC_OBJ_NUMANODE, nodeId);
    ASSERT_NE(numaNode, nullptr);

    // Setup initiator structure.
    struct hwloc_location initiator;
    initiator.location.cpuset = numaNode->cpuset;
    initiator.type = hwloc_location_type_alias::HWLOC_LOCATION_TYPE_CPUSET;

    hwloc_uint64_t value = 0;
    ret = hwloc_memattr_get_value(topology, HWLOC_MEMATTR_ID_BANDWIDTH,
                                  numaNode, &initiator, 0, &value);

    hwloc_topology_destroy(topology);

    if (ret != 0) {
        GTEST_SKIP()
            << "Error: hwloc_memattr_get_value return value is equal to " << ret
            << ", should be " << 0;
    }
}

INSTANTIATE_TEST_SUITE_P(memspaceLowestLatencyTest, memspaceGetTest,
                         ::testing::Values(memspaceGetParams{
                             canQueryBandwidth,
                             umfMemspaceHighestBandwidthGet}));

INSTANTIATE_TEST_SUITE_P(memspaceLowestLatencyProviderTest,
                         memspaceProviderTest,
                         ::testing::Values(memspaceGetParams{
                             canQueryBandwidth,
                             umfMemspaceHighestBandwidthGet}));

TEST_F(numaNodesTest, PerCoreBandwidthPlacement) {
    const size_t allocSize = 4096;
    unsigned int numCores = std::thread::hardware_concurrency();
    if (numCores == 0) {
        numCores = 1;
    }

    canQueryBandwidth(0);
    if (IS_SKIPPED_OR_FAILED()) {
        GTEST_SKIP() << "Error: hwloc_memattr_get_value returned 0";
    }

    std::vector<std::thread> workers;
    workers.reserve(numCores);

    for (unsigned int i = 0; i < numCores; ++i) {
        workers.emplace_back([cpuIndex = i]() {
            hwloc_topology_t topo = nullptr;
            ASSERT_EQ(hwloc_topology_init(&topo), 0);
            ASSERT_EQ(hwloc_topology_load(topo), 0);

            hwloc_bitmap_t target = hwloc_bitmap_alloc();
            hwloc_bitmap_only(target, cpuIndex);
            ASSERT_EQ(
                hwloc_set_cpubind(topo, target,
                                  HWLOC_CPUBIND_THREAD | HWLOC_CPUBIND_STRICT),
                0);
            hwloc_bitmap_free(target);

            hwloc_location initiator;
            hwloc_bitmap_t here = hwloc_bitmap_alloc();
            ASSERT_EQ(
                hwloc_get_cpubind(topo, here,
                                  HWLOC_CPUBIND_THREAD | HWLOC_CPUBIND_STRICT),
                0);
            initiator.location.cpuset = here;
            initiator.type = HWLOC_LOCATION_TYPE_CPUSET;

            hwloc_obj_t bestnode;
            hwloc_memattr_get_best_target(topo, HWLOC_MEMATTR_ID_BANDWIDTH,
                                          &initiator, 0, &bestnode, nullptr);

            void *ptr_hwloc = hwloc_alloc_membind(
                topo, allocSize, bestnode->nodeset, HWLOC_MEMBIND_BIND,
                HWLOC_MEMBIND_BYNODESET);
            ASSERT_NE(ptr_hwloc, nullptr);
            memset(ptr_hwloc, 0, allocSize);

            auto memspace = umfMemspaceHighestBandwidthGet();
            ASSERT_NE(memspace, nullptr);

            umf_memory_provider_handle_t provider;
            ASSERT_EQ(umfMemoryProviderCreateFromMemspace(memspace, nullptr,
                                                          &provider),
                      UMF_RESULT_SUCCESS);

            void *ptr_umf = nullptr;
            ASSERT_EQ(umfMemoryProviderAlloc(provider, allocSize, 0, &ptr_umf),
                      UMF_RESULT_SUCCESS);
            ASSERT_NE(ptr_umf, nullptr);
            memset(ptr_umf, 0, allocSize);

            ASSERT_NODE_EQ(ptr_umf, ptr_hwloc);

            umfMemoryProviderFree(provider, ptr_umf, allocSize);
            umfMemoryProviderDestroy(provider);
            hwloc_free(topo, ptr_hwloc, allocSize);
            hwloc_bitmap_free(here);
            hwloc_topology_destroy(topo);
        });
    }

    for (auto &t : workers) {
        t.join();
    }
}
