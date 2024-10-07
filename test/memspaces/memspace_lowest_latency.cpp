// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <umf/memspace.h>

#include "memspace_fixtures.hpp"
#include "memspace_helpers.hpp"
#include "memspace_internal.h"
#include "test_helpers.h"

static void canQueryLatency(size_t nodeId) {
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
    ret = hwloc_memattr_get_value(topology, HWLOC_MEMATTR_ID_LATENCY, numaNode,
                                  &initiator, 0, &value);

    hwloc_topology_destroy(topology);

    if (ret != 0) {
        GTEST_SKIP()
            << "Error: hwloc_memattr_get_value return value is equal to " << ret
            << ", should be " << 0;
    }
}

INSTANTIATE_TEST_SUITE_P(memspaceLowestLatencyTest, memspaceGetTest,
                         ::testing::Values(memspaceGetParams{
                             canQueryLatency, umfMemspaceLowestLatencyGet}));

INSTANTIATE_TEST_SUITE_P(memspaceLowestLatencyProviderTest,
                         memspaceProviderTest,
                         ::testing::Values(memspaceGetParams{
                             canQueryLatency, umfMemspaceLowestLatencyGet}));
