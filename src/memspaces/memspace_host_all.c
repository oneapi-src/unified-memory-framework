/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <assert.h>
#include <stdlib.h>

#include <umf.h>
#include <umf/memspace.h>

// UMF_MEMSPACE_HOST_ALL requires HWLOC
// Additionally, it is currently unsupported on Win

#if defined(_WIN32) || defined(UMF_NO_HWLOC)
umf_const_memspace_handle_t umfMemspaceHostAllGet(void) {
    // not supported
    return NULL;
}

#else // !defined(_WIN32) && !defined(UMF_NO_HWLOC)

#include "base_alloc_global.h"
#include "memspace_internal.h"
#include "memtarget_numa.h"
#include "topology.h"
#include "utils_concurrency.h"

static umf_result_t umfMemspaceHostAllCreate(umf_memspace_handle_t *hMemspace) {
    if (!hMemspace) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_result_t umf_ret = UMF_RESULT_SUCCESS;

    hwloc_topology_t topology = umfGetTopology();
    if (!topology) {
        // TODO: What would be an approrpiate err?
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    // Shouldn't return -1, as 'HWLOC_OBJ_NUMANODE' doesn't appear to be an
    // object that can be present on multiple levels.
    // Source: https://www.open-mpi.org/projects/hwloc/doc/hwloc-v2.10.0-letter.pdf
    int nNodes = hwloc_get_nbobjs_by_type(topology, HWLOC_OBJ_NUMANODE);
    if (nNodes < 0) {
        umf_ret = UMF_RESULT_ERROR_UNKNOWN;
        goto err;
    }

    unsigned *nodeIds = umf_ba_global_alloc(nNodes * sizeof(*nodeIds));
    if (!nodeIds) {
        umf_ret = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        goto err;
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

    umf_ba_global_free(nodeIds);

err:
    return umf_ret;
}

static umf_memspace_handle_t UMF_MEMSPACE_HOST_ALL = NULL;
static UTIL_ONCE_FLAG UMF_MEMSPACE_HOST_ALL_INITIALIZED = UTIL_ONCE_FLAG_INIT;

void umfMemspaceHostAllDestroy(void) {
    if (UMF_MEMSPACE_HOST_ALL) {
        umfMemspaceDestroy(UMF_MEMSPACE_HOST_ALL);
        UMF_MEMSPACE_HOST_ALL = NULL;

        // portable version of "UMF_MEMSPACE_HOST_ALL_INITIALIZED = UTIL_ONCE_FLAG_INIT;"
        static UTIL_ONCE_FLAG is_initialized = UTIL_ONCE_FLAG_INIT;
        memcpy(&UMF_MEMSPACE_HOST_ALL_INITIALIZED, &is_initialized,
               sizeof(UMF_MEMSPACE_HOST_ALL_INITIALIZED));
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

umf_const_memspace_handle_t umfMemspaceHostAllGet(void) {
    utils_init_once(&UMF_MEMSPACE_HOST_ALL_INITIALIZED, umfMemspaceHostAllInit);
    return UMF_MEMSPACE_HOST_ALL;
}

#endif // !defined(_WIN32) && !defined(UMF_NO_HWLOC)
