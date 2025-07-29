/*
 *
 * Copyright (C) 2024-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "base_alloc_global.h"
#include "umf_hwloc.h"
#include "utils_concurrency.h"
#include "utils_log.h"

static hwloc_topology_t topology = NULL;
static hwloc_bitmap_t topology2 = NULL;

static UTIL_ONCE_FLAG topology_initialized = UTIL_ONCE_FLAG_INIT;
static UTIL_ONCE_FLAG topology_initialized2 = UTIL_ONCE_FLAG_INIT;

void umfDestroyTopology(void) {
    if (topology) {
        hwloc_topology_destroy(topology);

        // portable version of "topology_initialized = UTIL_ONCE_FLAG_INIT;"
        static UTIL_ONCE_FLAG is_initialized = UTIL_ONCE_FLAG_INIT;
        memcpy(&topology_initialized, &is_initialized,
               sizeof(topology_initialized));

        static UTIL_ONCE_FLAG is_initialized2 = UTIL_ONCE_FLAG_INIT;
        memcpy(&topology_initialized2, &is_initialized2,
               sizeof(topology_initialized2));
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

int utils_get_complete_nodeset(size_t *nodes, size_t nodes_size, size_t *num) {
    DIR *dir = opendir("/sys/devices/system/node/");
    if (!dir) {
        return -1;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "node", 4) == 0) {
            char *endptr;
            long node_id = strtol(entry->d_name + 4, &endptr, 10);
            if (*endptr == '\0' && node_id >= 0 && *num < nodes_size) {
                nodes[*num] = (size_t)node_id;
                (*num)++;
            }
        }
    }

    closedir(dir);
    return 0;
}

static void umfCreateTopology2(void) {

    topology2 = hwloc_bitmap_alloc();

    size_t *nodes = umf_ba_global_alloc(sizeof(size_t) * 1024);
    if (!nodes) {
        return;
    }

    if (!topology2) {
        return;
    }

    size_t num = 0;
    int ret = utils_get_complete_nodeset(nodes, 1024, &num);
    if (ret < 0) {
        return;
    }

    for (size_t i = 0; i < num; i++) {
        hwloc_bitmap_set(topology2, (int)nodes[i]);
    }

    umf_ba_global_free(nodes);
}

hwloc_topology_t umfGetTopology(void) {
    utils_init_once(&topology_initialized, umfCreateTopology);
    return topology;
}

hwloc_bitmap_t umfGetTopology2(void) {
    utils_init_once(&topology_initialized2, umfCreateTopology2);
    return topology2;
}
