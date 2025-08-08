/*
 *
 * Copyright (C) 2024-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "base_alloc_global.h"
#include "umf_hwloc.h"
#include "utils_concurrency.h"
#include "utils_log.h"

static hwloc_topology_t topology = NULL;
static hwloc_topology_t topology_reduced = NULL;
static UTIL_ONCE_FLAG topology_initialized = UTIL_ONCE_FLAG_INIT;
static UTIL_ONCE_FLAG topology_reduced_initialized = UTIL_ONCE_FLAG_INIT;

void umfDestroyTopology(void) {
    if (topology) {
        hwloc_topology_destroy(topology);

        // portable version of "topology_initialized = UTIL_ONCE_FLAG_INIT;"
        static UTIL_ONCE_FLAG is_initialized = UTIL_ONCE_FLAG_INIT;
        memcpy(&topology_initialized, &is_initialized,
               sizeof(topology_initialized));
    }
    if (topology_reduced) {
        hwloc_topology_destroy(topology_reduced);

        // portable version of "topology_initialized = UTIL_ONCE_FLAG_INIT;"
        static UTIL_ONCE_FLAG is_initialized = UTIL_ONCE_FLAG_INIT;
        memcpy(&topology_reduced_initialized, &is_initialized,
               sizeof(topology_reduced_initialized));
    }
}

static void umfCreateTopologyHelper(bool reduced,
                                    hwloc_topology_t *topology_ptr) {
    if (hwloc_topology_init(topology_ptr)) {
        LOG_ERR("Failed to initialize topology");
        *topology_ptr = NULL;
        return;
    }

    if (reduced) {
        // Set the topology to only include NUMA nodes and memory
        // to improve performance of the topology load on large systems
        if (hwloc_topology_set_all_types_filter(*topology_ptr,
                                                HWLOC_TYPE_FILTER_KEEP_NONE)) {
            LOG_ERR("Failed to set topology filter");
            hwloc_topology_destroy(*topology_ptr);
            *topology_ptr = NULL;
            return;
        }
    }
    if (hwloc_topology_load(*topology_ptr)) {
        LOG_ERR("Failed to initialize topology");
        hwloc_topology_destroy(*topology_ptr);
        *topology_ptr = NULL;
    }
}

static void umfCreateTopology(void) {
    umfCreateTopologyHelper(false, &topology);
}

static void umfCreateTopologyReduced(void) {
    umfCreateTopologyHelper(true, &topology_reduced);
}

hwloc_topology_t umfGetTopologyReduced(void) {
    utils_init_once(&topology_reduced_initialized, umfCreateTopologyReduced);
    return topology_reduced;
}

hwloc_topology_t umfGetTopology(void) {
    utils_init_once(&topology_initialized, umfCreateTopology);
    return topology;
}
