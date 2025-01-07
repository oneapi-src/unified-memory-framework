/*
 *
 * Copyright (C) 2023-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <stdlib.h>

#include <umf.h>
#include <umf/memspace.h>

// umfMemspaceCreateFromNumaArray requires HWLOC
// Additionally, it is currently unsupported on Win
#if defined(_WIN32) || defined(UMF_NO_HWLOC)
umf_result_t umfMemspaceCreateFromNumaArray(unsigned *nodeIds, size_t numIds,
                                            umf_memspace_handle_t *hMemspace) {
    (void)nodeIds;
    (void)numIds;
    (void)hMemspace;

    // not supported
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

#else // !defined(_WIN32) && !defined(UMF_NO_HWLOC)

#include "../memspace_internal.h"
#include "../memtargets/memtarget_numa.h"
#include "base_alloc_global.h"

umf_result_t umfMemspaceCreateFromNumaArray(unsigned *nodeIds, size_t numIds,
                                            umf_memspace_handle_t *hMemspace) {
    if (!nodeIds || numIds == 0 || !hMemspace) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_result_t ret = UMF_RESULT_SUCCESS;
    umf_memspace_handle_t memspace =
        umf_ba_global_alloc(sizeof(struct umf_memspace_t));
    if (!memspace) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    memspace->size = numIds;
    memspace->nodes =
        umf_ba_global_alloc(memspace->size * sizeof(umf_memtarget_handle_t));
    if (!memspace->nodes) {
        ret = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        goto err_nodes_alloc;
    }

    size_t nodeIdx;
    for (nodeIdx = 0; nodeIdx < numIds; nodeIdx++) {
        struct umf_numa_memtarget_config_t config = {nodeIds[nodeIdx]};
        ret = umfMemtargetCreate(&UMF_MEMTARGET_NUMA_OPS, &config,
                                 &memspace->nodes[nodeIdx]);
        if (ret) {
            goto err_target_create;
        }
    }

    *hMemspace = memspace;

    return UMF_RESULT_SUCCESS;

err_target_create:
    umf_ba_global_free(memspace->nodes);
    for (size_t i = 0; i < nodeIdx; i++) {
        umfMemtargetDestroy(memspace->nodes[i]);
    }
err_nodes_alloc:
    umf_ba_global_free(memspace);
    return ret;
}

#endif // !defined(_WIN32) && !defined(UMF_NO_HWLOC)
