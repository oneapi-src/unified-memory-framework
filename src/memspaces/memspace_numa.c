/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <stdlib.h>

#include "../memory_targets/memory_target_numa.h"
#include "../memspace_internal.h"
#include <umf/memspaces/memspace_numa.h>

enum umf_result_t
umfMemspaceCreateFromNumaArray(size_t *nodeIds, size_t numIds,
                               umf_memspace_handle_t *hMemspace) {
    if (!nodeIds || numIds == 0 || !hMemspace) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    enum umf_result_t ret = UMF_RESULT_SUCCESS;
    umf_memspace_handle_t memspace =
        (struct umf_memspace_t *)malloc(sizeof(struct umf_memspace_t));
    if (!memspace) {
        ret = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        goto err_memspace_alloc;
    }

    memspace->size = numIds;
    memspace->nodes = (umf_memory_target_handle_t *)calloc(
        numIds, sizeof(umf_memory_target_handle_t));
    if (!memspace->nodes) {
        ret = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        goto err_nodes_alloc;
    }

    size_t nodeIdx;
    for (nodeIdx = 0; nodeIdx < numIds; nodeIdx++) {
        struct umf_numa_memory_target_config_t config = {nodeIds[nodeIdx]};
        ret = umfMemoryTargetCreate(&UMF_MEMORY_TARGET_NUMA_OPS, &config,
                                    &memspace->nodes[nodeIdx]);
        if (ret) {
            goto err_target_create;
        }
    }

    *hMemspace = memspace;

    return UMF_RESULT_SUCCESS;

err_target_create:
    for (size_t i = 0; i < nodeIdx; i++) {
        umfMemoryTargetDestroy(memspace->nodes[i]);
    }
    free(memspace->nodes);
err_nodes_alloc:
    free(memspace);
err_memspace_alloc:
    return ret;
}
