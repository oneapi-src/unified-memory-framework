/*
 *
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <assert.h>
#include <stdlib.h>

#include <umf/memspace.h>

#include "base_alloc_global.h"
#include "memory_target.h"
#include "memory_target_ops.h"
#include "memspace_internal.h"

#ifndef NDEBUG
static umf_result_t verifyMemTargetsTypes(umf_memspace_handle_t memspace) {
    assert(memspace);
    if (memspace->size == 0) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    const struct umf_memory_target_ops_t *ops = memspace->nodes[0]->ops;
    for (size_t i = 1; i < memspace->size; i++) {
        if (memspace->nodes[i]->ops != ops) {
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
    }

    return UMF_RESULT_SUCCESS;
}
#endif

static umf_result_t memoryTargetHandlesToPriv(umf_memspace_handle_t memspace,
                                              void ***pPrivs) {
    assert(memspace);
    void **privs = umf_ba_global_alloc(sizeof(void *) * memspace->size);
    if (privs == NULL) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    for (size_t i = 0; i < memspace->size; i++) {
        privs[i] = memspace->nodes[i]->priv;
    }
    *pPrivs = privs;

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfPoolCreateFromMemspace(umf_memspace_handle_t memspace,
                                       umf_memspace_policy_handle_t policy,
                                       umf_memory_pool_handle_t *pool) {
    if (!memspace || !pool) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    void **privs = NULL;
    umf_result_t ret = memoryTargetHandlesToPriv(memspace, &privs);
    if (ret != UMF_RESULT_SUCCESS) {
        return ret;
    }

    // TODO: for now, we only support memspaces that consist of memory_targets
    // of the same type. Fix this.
    assert(verifyMemTargetsTypes(memspace) == UMF_RESULT_SUCCESS);
    ret = memspace->nodes[0]->ops->pool_create_from_memspace(
        memspace, privs, memspace->size, policy, pool);

    umf_ba_global_free(privs);

    return ret;
}

umf_result_t
umfMemoryProviderCreateFromMemspace(umf_memspace_handle_t memspace,
                                    umf_memspace_policy_handle_t policy,
                                    umf_memory_provider_handle_t *provider) {
    if (!memspace || !provider) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    void **privs = NULL;
    umf_result_t ret = memoryTargetHandlesToPriv(memspace, &privs);
    if (ret != UMF_RESULT_SUCCESS) {
        return ret;
    }

    // TODO: for now, we only support memspaces that consist of memory_targets
    // of the same type. Fix this.
    assert(verifyMemTargetsTypes(memspace) == UMF_RESULT_SUCCESS);
    ret = memspace->nodes[0]->ops->memory_provider_create_from_memspace(
        memspace, privs, memspace->size, policy, provider);

    umf_ba_global_free(privs);

    return ret;
}

void umfMemspaceDestroy(umf_memspace_handle_t memspace) {
    assert(memspace);
    for (size_t i = 0; i < memspace->size; i++) {
        umfMemoryTargetDestroy(memspace->nodes[i]);
    }

    umf_ba_global_free(memspace->nodes);
    umf_ba_global_free(memspace);
}

umf_result_t umfMemspaceClone(umf_memspace_handle_t hMemspace,
                              umf_memspace_handle_t *outHandle) {
    if (!hMemspace || !outHandle) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_memspace_handle_t clone =
        umf_ba_global_alloc(sizeof(struct umf_memspace_t));
    if (!clone) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    clone->size = hMemspace->size;
    clone->nodes =
        umf_ba_global_alloc(sizeof(umf_memory_target_handle_t) * clone->size);
    if (!clone->nodes) {
        umf_ba_global_free(clone);
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    size_t i;
    umf_result_t ret;

    for (i = 0; i < clone->size; i++) {
        ret = umfMemoryTargetClone(hMemspace->nodes[i], &clone->nodes[i]);
        if (ret != UMF_RESULT_SUCCESS) {
            goto err;
        }
    }

    *outHandle = clone;

    return UMF_RESULT_SUCCESS;
err:
    while (i != 0) {
        i--;
        umfMemoryTargetDestroy(clone->nodes[i]);
    }
    umf_ba_global_free(clone->nodes);
    umf_ba_global_free(clone);
    return ret;
}

struct memory_target_sort_entry {
    uint64_t property;
    umf_memory_target_handle_t node;
};

static int propertyCmp(const void *a, const void *b) {
    const struct memory_target_sort_entry *entryA = a;
    const struct memory_target_sort_entry *entryB = b;

    if (entryA->property < entryB->property) {
        return 1;
    } else if (entryA->property > entryB->property) {
        return -1;
    } else {
        return 0;
    }
}

umf_result_t
umfMemspaceSortDesc(umf_memspace_handle_t hMemspace,
                    umf_result_t (*getProperty)(umf_memory_target_handle_t node,
                                                uint64_t *property)) {
    if (!hMemspace || !getProperty) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    struct memory_target_sort_entry *entries = umf_ba_global_alloc(
        sizeof(struct memory_target_sort_entry) * hMemspace->size);
    if (!entries) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    // create temporary array that contains desired property values for sorting
    for (size_t i = 0; i < hMemspace->size; i++) {
        entries[i].node = hMemspace->nodes[i];
        umf_result_t ret =
            getProperty(hMemspace->nodes[i], &entries[i].property);
        if (ret != UMF_RESULT_SUCCESS) {
            umf_ba_global_free(entries);
            return ret;
        }
    }

    qsort(entries, hMemspace->size, sizeof(struct memory_target_sort_entry),
          propertyCmp);

    // apply the order to the original array
    for (size_t i = 0; i < hMemspace->size; i++) {
        hMemspace->nodes[i] = entries[i].node;
    }

    umf_ba_global_free(entries);

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfMemspaceFilter(umf_memspace_handle_t hMemspace,
                               umfGetTargetFn getTarget,
                               umf_memspace_handle_t *filteredMemspace) {
    if (!hMemspace || !getTarget) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_memory_target_handle_t *uniqueBestNodes =
        umf_ba_global_alloc(hMemspace->size * sizeof(*uniqueBestNodes));
    if (!uniqueBestNodes) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    umf_result_t ret = UMF_RESULT_SUCCESS;

    size_t numUniqueBestNodes = 0;
    for (size_t nodeIdx = 0; nodeIdx < hMemspace->size; nodeIdx++) {
        umf_memory_target_handle_t target = NULL;
        ret = getTarget(hMemspace->nodes[nodeIdx], hMemspace->nodes,
                        hMemspace->size, &target);
        if (ret != UMF_RESULT_SUCCESS) {
            goto err_free_best_targets;
        }

        // check if the target is already present in the best nodes
        size_t bestTargetIdx;
        for (bestTargetIdx = 0; bestTargetIdx < numUniqueBestNodes;
             bestTargetIdx++) {
            if (uniqueBestNodes[bestTargetIdx] == target) {
                break;
            }
        }

        // if the target is not present, add it to the best nodes
        if (bestTargetIdx == numUniqueBestNodes) {
            uniqueBestNodes[numUniqueBestNodes++] = target;
        }
    }

    // copy the unique best nodes into a new memspace
    umf_memspace_handle_t newMemspace =
        umf_ba_global_alloc(sizeof(*newMemspace));
    if (!newMemspace) {
        ret = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        goto err_free_best_targets;
    }

    newMemspace->size = numUniqueBestNodes;
    newMemspace->nodes =
        umf_ba_global_alloc(sizeof(*newMemspace->nodes) * newMemspace->size);
    if (!newMemspace->nodes) {
        ret = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        goto err_free_new_memspace;
    }

    size_t cloneIdx = 0;
    for (size_t cloneIdx = 0; cloneIdx < newMemspace->size; cloneIdx++) {
        ret = umfMemoryTargetClone(uniqueBestNodes[cloneIdx],
                                   &newMemspace->nodes[cloneIdx]);
        if (ret != UMF_RESULT_SUCCESS) {
            goto err_free_cloned_nodes;
        }
    }

    *filteredMemspace = newMemspace;
    umf_ba_global_free(uniqueBestNodes);

    return UMF_RESULT_SUCCESS;

err_free_cloned_nodes:
    while (cloneIdx != 0) {
        cloneIdx--;
        umfMemoryTargetDestroy(newMemspace->nodes[cloneIdx]);
    }
    umf_ba_global_free(newMemspace->nodes);
err_free_new_memspace:
    umf_ba_global_free(newMemspace);
err_free_best_targets:
    umf_ba_global_free(uniqueBestNodes);
    return ret;
}
