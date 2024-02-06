/*
 *
 * Copyright (C) 2023 Intel Corporation
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
    void **privs = umf_ba_linear_alloc(memspace->linear_allocator,
                                       sizeof(void *) * memspace->size);
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
    // privs is freed during destroying memspace->linear_allocator

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
    // privs is freed during destroying memspace->linear_allocator

    return ret;
}

void umfMemspaceDestroy(umf_memspace_handle_t memspace) {
    assert(memspace);
    for (size_t i = 0; i < memspace->size; i++) {
        umfMemoryTargetDestroy(memspace->nodes[i]);
    }

    umf_ba_linear_destroy(memspace->linear_allocator);
    umf_ba_global_free(memspace, sizeof(struct umf_memspace_t));
}
