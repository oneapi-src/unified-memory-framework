/*
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <assert.h>
#include <string.h>

#include <umf.h>
#include <umf/memory_provider.h>
#include <umf/memory_provider_ops.h>

#include "provider_deprecated.h"

umf_result_t umfDefaultFree_0_10(void *provider, void *ptr, size_t size) {
    (void)provider;
    (void)ptr;
    (void)size;
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

umf_result_t
umfTranslateMemoryProviderOps_0_10(umf_memory_provider_ops_0_10_t *ops_0_10,
                                   umf_memory_provider_ops_t *ops) {
    ops->version = UMF_PROVIDER_OPS_VERSION_CURRENT;
    ops->alloc = ops_0_10->alloc;

    // in UMF 0.10 the free() was a part of ext and could be NULL
    if (ops_0_10->ext.free != NULL) {
        ops->free = ops_0_10->ext.free;
    } else {
        ops->free = umfDefaultFree_0_10;
    }

    ops->get_last_native_error = ops_0_10->get_last_native_error;
    ops->get_recommended_page_size = ops_0_10->get_recommended_page_size;
    ops->get_min_page_size = ops_0_10->get_min_page_size;
    ops->get_name = ops_0_10->get_name;
    ops->initialize = ops_0_10->initialize;
    ops->finalize = ops_0_10->finalize;

    ops->ext.purge_lazy = ops_0_10->ext.purge_lazy;
    ops->ext.purge_force = ops_0_10->ext.purge_force;
    ops->ext.allocation_merge = ops_0_10->ext.allocation_merge;
    ops->ext.allocation_split = ops_0_10->ext.allocation_split;

    // IPC hasn't changed
    assert(sizeof(umf_memory_provider_ipc_ops_t) ==
           sizeof(umf_memory_provider_ipc_ops_0_10_t));
    memcpy(&ops->ipc, &ops_0_10->ipc, sizeof(ops_0_10->ipc));

    return UMF_RESULT_SUCCESS;
}
