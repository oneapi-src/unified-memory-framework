/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */
#include <umf/mempolicy.h>

#include "base_alloc_global.h"
#include "mempolicy_internal.h"

umf_result_t umfMempolicyCreate(umf_mempolicy_membind_t bind,
                                umf_mempolicy_handle_t *policy) {
    if (policy == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *policy = umf_ba_global_alloc(sizeof(**policy));

    if (*policy == NULL) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    (*policy)->type = bind;
    if (bind == UMF_MEMPOLICY_INTERLEAVE) {
        (*policy)->ops.interleave.part_size = 0;
    } else if (bind == UMF_MEMPOLICY_SPLIT) {
        (*policy)->ops.split.part_len = 0;
    }

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfMempolicyDestroy(umf_mempolicy_handle_t policy) {
    umf_ba_global_free(policy);
    return UMF_RESULT_SUCCESS;
}

umf_result_t umfMempolicySetInterleavePartSize(umf_mempolicy_handle_t policy,
                                               size_t partSize) {
    if (policy == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (policy->type != UMF_MEMPOLICY_INTERLEAVE) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    policy->ops.interleave.part_size = partSize;
    return UMF_RESULT_SUCCESS;
}

umf_result_t
umfMempolicySetCustomSplitPartitions(umf_mempolicy_handle_t policy,
                                     umf_mempolicy_split_partition_t *partList,
                                     size_t partListLen) {
    if (policy == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    if (policy->type != UMF_MEMPOLICY_SPLIT) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    policy->ops.split.part = partList;
    policy->ops.split.part_len = partListLen;
    return UMF_RESULT_SUCCESS;
}
