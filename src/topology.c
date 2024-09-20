/*
 *
 * Copyright (C) 2024 Intel Corporation
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
static UTIL_ONCE_FLAG topology_initialized = UTIL_ONCE_FLAG_INIT;

void umfDestroyTopology(void) {
    if (topology) {
        hwloc_topology_destroy(topology);

        // portable version of "topology_initialized = UTIL_ONCE_FLAG_INIT;"
        static UTIL_ONCE_FLAG is_initialized = UTIL_ONCE_FLAG_INIT;
        memcpy(&topology_initialized, &is_initialized,
               sizeof(topology_initialized));
    }
}

static void umfCreateTopology(void) {
    if (hwloc_topology_init(&topology)) {
        LOG_ERR("Failed to initialize topology");
        topology = NULL;
        return;
    }

    if (hwloc_topology_load(topology)) {
        LOG_ERR("Failed to initialize topology");
        hwloc_topology_destroy(topology);
        topology = NULL;
    }
}

hwloc_topology_t umfGetTopology(void) {
    utils_init_once(&topology_initialized, umfCreateTopology);
    return topology;
}
