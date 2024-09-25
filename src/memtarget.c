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

#include "base_alloc_global.h"
#include "libumf.h"
#include "memtarget_internal.h"
#include "memtarget_ops.h"
#include "utils_concurrency.h"

umf_result_t umfMemtargetCreate(const umf_memtarget_ops_t *ops, void *params,
                                umf_memtarget_handle_t *memoryTarget) {
    libumfInit();
    if (!ops || !memoryTarget) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_memtarget_handle_t target =
        umf_ba_global_alloc(sizeof(umf_memtarget_t));
    if (!target) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    assert(ops->version == UMF_VERSION_CURRENT);

    target->ops = ops;

    void *target_priv;
    umf_result_t ret = ops->initialize(params, &target_priv);
    if (ret != UMF_RESULT_SUCCESS) {
        umf_ba_global_free(target);
        return ret;
    }

    target->priv = target_priv;

    *memoryTarget = target;

    return UMF_RESULT_SUCCESS;
}

void umfMemtargetDestroy(umf_memtarget_handle_t memoryTarget) {
    assert(memoryTarget);
    memoryTarget->ops->finalize(memoryTarget->priv);
    umf_ba_global_free(memoryTarget);
}

umf_result_t umfMemtargetClone(umf_const_memtarget_handle_t memoryTarget,
                               umf_memtarget_handle_t *outHandle) {
    assert(memoryTarget);
    assert(outHandle);

    *outHandle = umf_ba_global_alloc(sizeof(umf_memtarget_t));
    if (!*outHandle) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    void *outPriv;
    umf_result_t ret = memoryTarget->ops->clone(memoryTarget->priv, &outPriv);
    if (ret != UMF_RESULT_SUCCESS) {
        umf_ba_global_free(*outHandle);
        return ret;
    }

    (*outHandle)->ops = memoryTarget->ops;
    (*outHandle)->priv = outPriv;

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfMemtargetGetCapacity(umf_const_memtarget_handle_t memoryTarget,
                                     size_t *capacity) {
    if (!memoryTarget || !capacity) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    return memoryTarget->ops->get_capacity(memoryTarget->priv, capacity);
}

umf_result_t umfMemtargetGetBandwidth(umf_memtarget_handle_t srcMemoryTarget,
                                      umf_memtarget_handle_t dstMemoryTarget,
                                      size_t *bandwidth) {
    if (!srcMemoryTarget || !dstMemoryTarget || !bandwidth) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    return srcMemoryTarget->ops->get_bandwidth(
        srcMemoryTarget->priv, dstMemoryTarget->priv, bandwidth);
}

umf_result_t umfMemtargetGetLatency(umf_memtarget_handle_t srcMemoryTarget,
                                    umf_memtarget_handle_t dstMemoryTarget,
                                    size_t *latency) {
    if (!srcMemoryTarget || !dstMemoryTarget || !latency) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    return srcMemoryTarget->ops->get_latency(srcMemoryTarget->priv,
                                             dstMemoryTarget->priv, latency);
}

umf_result_t umfMemtargetGetId(umf_const_memtarget_handle_t hMemtarget,
                               unsigned *id) {
    if (!hMemtarget || !id) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    return hMemtarget->ops->get_id(hMemtarget->priv, id);
}

umf_result_t umfMemtargetGetType(umf_const_memtarget_handle_t memoryTarget,
                                 umf_memtarget_type_t *type) {
    if (!memoryTarget || !type) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    return memoryTarget->ops->get_type(memoryTarget->priv, type);
}

umf_result_t umfMemtargetCompare(umf_const_memtarget_handle_t a,
                                 umf_const_memtarget_handle_t b, int *result) {
    umf_memtarget_type_t typeA, typeB;
    umf_result_t ret = umfMemtargetGetType(a, &typeA);
    if (ret != UMF_RESULT_SUCCESS) {
        return ret;
    }

    ret = umfMemtargetGetType(b, &typeB);
    if (ret != UMF_RESULT_SUCCESS) {
        return ret;
    }

    if (typeA != typeB) {
        *result = -1;
        return UMF_RESULT_SUCCESS;
    }

    ret = a->ops->compare(a->priv, b->priv, result);
    if (ret != UMF_RESULT_SUCCESS) {
        return ret;
    }

    if (*result) {
        *result = 1;
    }

    return UMF_RESULT_SUCCESS;
}
