/*
 *
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "memory_pool_internal.h"

#include <umf/memory_pool.h>
#include <umf/memory_pool_ops.h>

#include <assert.h>
#include <stdlib.h>

umf_result_t umfPoolCreate(const umf_memory_pool_ops_t *ops,
                           umf_memory_provider_handle_t provider, void *params,
                           umf_pool_create_flags_t flags,
                           umf_memory_pool_handle_t *hPool) {
    umf_result_t ret = umfPoolCreateInternal(ops, provider, params, hPool);
    if (ret != UMF_RESULT_SUCCESS) {
        return ret;
    }
    assert(*hPool != NULL);
    (*hPool)->own_provider = (flags & UMF_POOL_CREATE_FLAG_OWN_PROVIDER);

    return UMF_RESULT_SUCCESS;
}

void *umfPoolMalloc(umf_memory_pool_handle_t hPool, size_t size) {
    return hPool->ops.malloc(hPool->pool_priv, size);
}

void *umfPoolAlignedMalloc(umf_memory_pool_handle_t hPool, size_t size,
                           size_t alignment) {
    return hPool->ops.aligned_malloc(hPool->pool_priv, size, alignment);
}

void *umfPoolCalloc(umf_memory_pool_handle_t hPool, size_t num, size_t size) {
    return hPool->ops.calloc(hPool->pool_priv, num, size);
}

void *umfPoolRealloc(umf_memory_pool_handle_t hPool, void *ptr, size_t size) {
    return hPool->ops.realloc(hPool->pool_priv, ptr, size);
}

size_t umfPoolMallocUsableSize(umf_memory_pool_handle_t hPool, void *ptr) {
    return hPool->ops.malloc_usable_size(hPool->pool_priv, ptr);
}

umf_result_t umfPoolFree(umf_memory_pool_handle_t hPool, void *ptr) {
    return hPool->ops.free(hPool->pool_priv, ptr);
}

umf_result_t umfPoolGetLastAllocationError(umf_memory_pool_handle_t hPool) {
    return hPool->ops.get_last_allocation_error(hPool->pool_priv);
}
