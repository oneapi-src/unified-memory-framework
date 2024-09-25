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
#include "memspace_internal.h"
#include "memtarget_internal.h"
#include "memtarget_ops.h"
#include "utils_log.h"

#ifndef NDEBUG
static umf_result_t
verifyMemTargetsTypes(umf_const_memspace_handle_t memspace) {
    assert(memspace);
    if (memspace->size == 0) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    const struct umf_memtarget_ops_t *ops = memspace->nodes[0]->ops;
    for (size_t i = 1; i < memspace->size; i++) {
        if (memspace->nodes[i]->ops != ops) {
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
    }

    return UMF_RESULT_SUCCESS;
}
#endif

static umf_result_t
memoryTargetHandlesToPriv(umf_const_memspace_handle_t memspace,
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

umf_result_t umfPoolCreateFromMemspace(umf_const_memspace_handle_t memspace,
                                       umf_const_mempolicy_handle_t policy,
                                       umf_memory_pool_handle_t *pool) {
    if (!memspace || !pool) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (memspace->size == 0) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    void **privs = NULL;
    umf_result_t ret = memoryTargetHandlesToPriv(memspace, &privs);
    if (ret != UMF_RESULT_SUCCESS) {
        return ret;
    }

    // TODO: for now, we only support memspaces that consist of memtargets
    // of the same type. Fix this.
    assert(verifyMemTargetsTypes(memspace) == UMF_RESULT_SUCCESS);
    ret = memspace->nodes[0]->ops->pool_create_from_memspace(
        memspace, privs, memspace->size, policy, pool);

    umf_ba_global_free(privs);

    return ret;
}

umf_result_t
umfMemoryProviderCreateFromMemspace(umf_const_memspace_handle_t memspace,
                                    umf_const_mempolicy_handle_t policy,
                                    umf_memory_provider_handle_t *provider) {
    if (!memspace || !provider) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (memspace->size == 0) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    void **privs = NULL;
    umf_result_t ret = memoryTargetHandlesToPriv(memspace, &privs);
    if (ret != UMF_RESULT_SUCCESS) {
        return ret;
    }

    // TODO: for now, we only support memspaces that consist of memtargets
    // of the same type. Fix this.
    assert(verifyMemTargetsTypes(memspace) == UMF_RESULT_SUCCESS);
    ret = memspace->nodes[0]->ops->memory_provider_create_from_memspace(
        memspace, privs, memspace->size, policy, provider);

    umf_ba_global_free(privs);

    return ret;
}

umf_result_t umfMemspaceNew(umf_memspace_handle_t *hMemspace) {
    if (!hMemspace) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_memspace_handle_t memspace =
        umf_ba_global_alloc(sizeof(struct umf_memspace_t));
    if (!memspace) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    memspace->size = 0;
    memspace->nodes = NULL;

    *hMemspace = memspace;

    return UMF_RESULT_SUCCESS;
}

void umfMemspaceDestroy(umf_memspace_handle_t memspace) {
    assert(memspace);
    for (size_t i = 0; i < memspace->size; i++) {
        umfMemtargetDestroy(memspace->nodes[i]);
    }

    umf_ba_global_free(memspace->nodes);
    umf_ba_global_free(memspace);
}

umf_result_t umfMemspaceClone(umf_const_memspace_handle_t hMemspace,
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
        umf_ba_global_alloc(sizeof(umf_memtarget_handle_t) * clone->size);
    if (!clone->nodes) {
        umf_ba_global_free(clone);
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    size_t i;
    umf_result_t ret;

    for (i = 0; i < clone->size; i++) {
        ret = umfMemtargetClone(hMemspace->nodes[i], &clone->nodes[i]);
        if (ret != UMF_RESULT_SUCCESS) {
            goto err;
        }
    }

    *outHandle = clone;

    return UMF_RESULT_SUCCESS;
err:
    while (i != 0) {
        i--;
        umfMemtargetDestroy(clone->nodes[i]);
    }
    umf_ba_global_free(clone->nodes);
    umf_ba_global_free(clone);
    return ret;
}

struct memtarget_sort_entry {
    uint64_t property;
    umf_memtarget_handle_t node;
};

static int propertyCmp(const void *a, const void *b) {
    const struct memtarget_sort_entry *entryA = a;
    const struct memtarget_sort_entry *entryB = b;

    if (entryA->property < entryB->property) {
        return 1;
    } else if (entryA->property > entryB->property) {
        return -1;
    } else {
        return 0;
    }
}

umf_result_t umfMemspaceSortDesc(umf_memspace_handle_t hMemspace,
                                 umfGetPropertyFn getProperty) {
    if (!hMemspace || !getProperty) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    struct memtarget_sort_entry *entries = umf_ba_global_alloc(
        sizeof(struct memtarget_sort_entry) * hMemspace->size);
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

    qsort(entries, hMemspace->size, sizeof(struct memtarget_sort_entry),
          propertyCmp);

    // apply the order to the original array
    for (size_t i = 0; i < hMemspace->size; i++) {
        hMemspace->nodes[i] = entries[i].node;
    }

    umf_ba_global_free(entries);

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfMemspaceFilter(umf_const_memspace_handle_t hMemspace,
                               umfGetTargetFn getTarget,
                               umf_memspace_handle_t *filteredMemspace) {
    if (!hMemspace || !getTarget) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_memtarget_handle_t *uniqueBestNodes =
        umf_ba_global_alloc(hMemspace->size * sizeof(*uniqueBestNodes));
    if (!uniqueBestNodes) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    umf_result_t ret = UMF_RESULT_SUCCESS;

    size_t numUniqueBestNodes = 0;
    for (size_t nodeIdx = 0; nodeIdx < hMemspace->size; nodeIdx++) {
        umf_memtarget_handle_t target = NULL;
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
    for (cloneIdx = 0; cloneIdx < newMemspace->size; cloneIdx++) {
        ret = umfMemtargetClone(uniqueBestNodes[cloneIdx],
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
        umfMemtargetDestroy(newMemspace->nodes[cloneIdx]);
    }
    umf_ba_global_free(newMemspace->nodes);
err_free_new_memspace:
    umf_ba_global_free(newMemspace);
err_free_best_targets:
    umf_ba_global_free(uniqueBestNodes);
    return ret;
}

size_t umfMemspaceMemtargetNum(umf_const_memspace_handle_t hMemspace) {
    if (!hMemspace) {
        return 0;
    }
    return hMemspace->size;
}

umf_const_memtarget_handle_t
umfMemspaceMemtargetGet(umf_const_memspace_handle_t hMemspace,
                        unsigned targetNum) {
    if (!hMemspace || targetNum >= hMemspace->size) {
        return NULL;
    }
    return hMemspace->nodes[targetNum];
}

umf_result_t umfMemspaceMemtargetAdd(umf_memspace_handle_t hMemspace,
                                     umf_const_memtarget_handle_t hMemtarget) {
    if (!hMemspace || !hMemtarget) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    for (size_t i = 0; i < hMemspace->size; i++) {
        int cmp;
        umf_result_t ret =
            umfMemtargetCompare(hMemspace->nodes[i], hMemtarget, &cmp);
        if (ret != UMF_RESULT_SUCCESS) {
            return ret;
        }

        if (cmp == 0) {
            LOG_ERR("Memory target already exists in the memspace");
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        } else if (cmp < 0) {
            LOG_ERR("You can't mix different memory target types in the same "
                    "memspace");
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
    }

    umf_memtarget_handle_t *newNodes =
        umf_ba_global_alloc(sizeof(*newNodes) * (hMemspace->size + 1));
    if (!newNodes) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    for (size_t i = 0; i < hMemspace->size; i++) {
        newNodes[i] = hMemspace->nodes[i];
    }
    umf_memtarget_t *hMemtargetClone;

    umf_result_t ret = umfMemtargetClone(hMemtarget, &hMemtargetClone);
    if (ret != UMF_RESULT_SUCCESS) {
        umf_ba_global_free(newNodes);
        return ret;
    }
    newNodes[hMemspace->size++] = hMemtargetClone;

    umf_ba_global_free(hMemspace->nodes);
    hMemspace->nodes = newNodes;
    return UMF_RESULT_SUCCESS;
}

umf_result_t
umfMemspaceMemtargetRemove(umf_memspace_handle_t hMemspace,
                           umf_const_memtarget_handle_t hMemtarget) {
    if (!hMemspace || !hMemtarget) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    unsigned i;
    for (i = 0; i < hMemspace->size; i++) {
        int cmp;
        umf_result_t ret =
            umfMemtargetCompare(hMemspace->nodes[i], hMemtarget, &cmp);

        if (ret != UMF_RESULT_SUCCESS) {
            return ret;
        }

        if (cmp == 0) {
            break;
        }
    }

    if (i == hMemspace->size) {
        LOG_ERR("Memory target not found in the memspace");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_memtarget_handle_t *newNodes =
        umf_ba_global_alloc(sizeof(*newNodes) * (hMemspace->size - 1));
    if (!newNodes) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    for (unsigned j = 0, z = 0; j < hMemspace->size; j++) {
        if (j != i) {
            newNodes[z++] = hMemspace->nodes[j];
        }
    }

    umfMemtargetDestroy(hMemspace->nodes[i]);
    umf_ba_global_free(hMemspace->nodes);
    hMemspace->nodes = newNodes;
    hMemspace->size--;
    return UMF_RESULT_SUCCESS;
}

// Helper function - returns zero on success, negative in case of error in filter function
// and positive error code, in case of other errors.
static int umfMemspaceFilterHelper(umf_memspace_handle_t memspace,
                                   umf_memspace_filter_func_t filter,
                                   void *args) {

    if (!memspace || !filter) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    size_t idx = 0;
    int ret;
    umf_memtarget_handle_t *nodesToRemove =
        umf_ba_global_alloc(sizeof(*nodesToRemove) * memspace->size);
    if (!nodesToRemove) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    for (size_t i = 0; i < memspace->size; i++) {
        ret = filter(memspace, memspace->nodes[i], args);
        if (ret < 0) {
            LOG_ERR("filter function failed");
            goto free_mem;
        } else if (ret == 0) {
            nodesToRemove[idx++] = memspace->nodes[i];
        }
    }

    size_t i = 0;
    for (; i < idx; i++) {
        ret = umfMemspaceMemtargetRemove(memspace, nodesToRemove[i]);
        if (ret != UMF_RESULT_SUCCESS) {
            goto re_add;
        }
    }

    umf_ba_global_free(nodesToRemove);
    return UMF_RESULT_SUCCESS;

re_add:
    // If target removal failed, add back previously removed targets.
    for (size_t j = 0; j < i; j++) {
        umf_result_t ret2 = umfMemspaceMemtargetAdd(memspace, nodesToRemove[j]);
        if (ret2 != UMF_RESULT_SUCCESS) {
            ret =
                UMF_RESULT_ERROR_UNKNOWN; // indicate that memspace is corrupted
            break;
        }
    }
free_mem:
    umf_ba_global_free(nodesToRemove);
    return ret;
}

umf_result_t umfMemspaceUserFilter(umf_memspace_handle_t memspace,
                                   umf_memspace_filter_func_t filter,
                                   void *args) {

    if (!memspace || !filter) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    int ret = umfMemspaceFilterHelper(memspace, filter, args);
    if (ret < 0) {
        return UMF_RESULT_ERROR_USER_SPECIFIC;
    }

    return ret;
}

typedef struct filter_by_id_args {
    unsigned *ids; // array of numa nodes ids
    size_t size;   // size of the array
} filter_by_id_args_t;

/*
 * The following predefined filter callbacks returns umf_result_t codes as negative value
 * because only negative values are treated as errors. umfMemspaceFilterHelper() will pass
 * this error code through and umfMemspaceFilterBy*() functions will translate this code to positive
 * umf_result_t code.
 */

static int filterById(umf_const_memspace_handle_t memspace,
                      umf_const_memtarget_handle_t target, void *args) {
    if (!memspace || !target || !args) {
        return -UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    filter_by_id_args_t *filterArgs = args;
    for (size_t i = 0; i < filterArgs->size; i++) {
        unsigned id;
        umf_result_t ret = umfMemtargetGetId(target, &id);
        if (ret != UMF_RESULT_SUCCESS) {
            return -ret;
        }

        if (id == filterArgs->ids[i]) {
            return 1;
        }
    }
    return 0;
}

static int filterByCapacity(umf_const_memspace_handle_t memspace,
                            umf_const_memtarget_handle_t target, void *args) {
    if (!memspace || !target || !args) {
        return -UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    size_t capacity;
    umf_result_t ret = umfMemtargetGetCapacity(target, &capacity);
    if (ret != UMF_RESULT_SUCCESS) {
        return -ret;
    }

    size_t *targetCapacity = args;
    return (capacity >= *targetCapacity) ? 1 : 0;
}

umf_result_t umfMemspaceFilterById(umf_memspace_handle_t memspace,
                                   unsigned *ids, size_t size) {
    if (!memspace || !ids || size == 0) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    filter_by_id_args_t args = {ids, size};
    int ret = umfMemspaceFilterHelper(memspace, &filterById, &args);

    // if umfMemspaceFilter() returned negative umf_result_t change it to positive
    return ret < 0 ? -ret : ret;
}

umf_result_t umfMemspaceFilterByCapacity(umf_memspace_handle_t memspace,
                                         int64_t capacity) {
    if (!memspace) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    // TODO: At this moment this function filters out memory targets that capacity is
    // less than specified size. We can extend this function to support reverse filter,
    // by using negative values of capacity parameter.
    // For now we just return invalid argument.
    if (capacity < 0) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    int ret = umfMemspaceFilterHelper(memspace, &filterByCapacity, &capacity);

    // if umfMemspaceFilter() returned negative umf_result_t change it to positive
    return ret < 0 ? -ret : ret;
}
