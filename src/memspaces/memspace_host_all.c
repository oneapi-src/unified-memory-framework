/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <assert.h>
#include <hwloc.h>
#include <stdlib.h>

#include "base_alloc_global.h"
#include "memory_target_numa.h"
#include "memspace_host_all_internal.h"
#include "memspace_internal.h"
#include "memspace_numa.h"
#include "utils_concurrency.h"

static umf_result_t umfMemspaceHostAllCreate(umf_memspace_handle_t *hMemspace) {
    if (!hMemspace) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_result_t umf_ret = UMF_RESULT_SUCCESS;

    hwloc_topology_t topology;
    if (hwloc_topology_init(&topology)) {
        // TODO: What would be an approrpiate err?
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    if (hwloc_topology_load(topology)) {
        umf_ret = UMF_RESULT_ERROR_UNKNOWN;
        goto err_topology_destroy;
    }

    // Shouldn't return -1, as 'HWLOC_OBJ_NUMANODE' doesn't appear to be an
    // object that can be present on multiple levels.
    // Source: https://www.open-mpi.org/projects/hwloc/doc/hwloc-v2.10.0-letter.pdf
    int nNodes = hwloc_get_nbobjs_by_type(topology, HWLOC_OBJ_NUMANODE);
    assert(nNodes != -1);

    size_t *nodeIds = umf_ba_global_alloc(nNodes * sizeof(size_t));
    if (!nodeIds) {
        umf_ret = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        goto err_topology_destroy;
    }

    // Collect all available NUMA node ids on the platform
    int nodeIdx = 0;
    hwloc_obj_t numaNodeObj = NULL;
    while ((numaNodeObj = hwloc_get_next_obj_by_type(
                topology, HWLOC_OBJ_NUMANODE, numaNodeObj)) != NULL) {
        // Shouldn't be possible to iterate over more 'HWLOC_OBJ_NUMANODE' objects
        // than the number returned by hwloc_get_nbobjs_by_type.
        assert(nodeIdx < nNodes);
        nodeIds[nodeIdx++] = numaNodeObj->os_index;
    }

    umf_ret =
        umfMemspaceCreateFromNumaArray(nodeIds, (size_t)nNodes, hMemspace);

    umf_ba_global_free(nodeIds, nNodes * sizeof(size_t));

err_topology_destroy:
    hwloc_topology_destroy(topology);
    return umf_ret;
}

static umf_memspace_handle_t UMF_MEMSPACE_HOST_ALL = NULL;
static UTIL_ONCE_FLAG UMF_MEMSPACE_HOST_ALL_INITIALIZED = UTIL_ONCE_FLAG_INIT;

void umfMemspaceHostAllDestroy(void) {
    if (UMF_MEMSPACE_HOST_ALL) {
        umfMemspaceDestroy(UMF_MEMSPACE_HOST_ALL);
        UMF_MEMSPACE_HOST_ALL = NULL;
    }
}

static void umfMemspaceHostAllInit(void) {
    umf_result_t ret = umfMemspaceHostAllCreate(&UMF_MEMSPACE_HOST_ALL);
    assert(ret == UMF_RESULT_SUCCESS);
    (void)ret;

    // TODO: Setup appropriate cleanup when 'HOST ALL' memspace becomes available
    // on Windows. 'HOST ALL' memspace depends on OS provider, which currently
    // doesn't support Windows.
}

umf_memspace_handle_t umfMemspaceHostAllGet(void) {
    util_init_once(&UMF_MEMSPACE_HOST_ALL_INITIALIZED, umfMemspaceHostAllInit);
    return UMF_MEMSPACE_HOST_ALL;
}
