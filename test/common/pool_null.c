// Copyright (C) 2023 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <assert.h>
#include <stdlib.h>

#include "pool_null.h"
#include <umf/memory_pool_ops.h>

static umf_result_t nullInitialize(umf_memory_provider_handle_t provider,
                                   void *params, void **pool) {
    (void)provider;
    (void)params;
    assert(provider);
    *pool = NULL;
    return UMF_RESULT_SUCCESS;
}

static void nullFinalize(void *pool) { (void)pool; }

static void *nullMalloc(void *pool, size_t size) {
    (void)pool;
    (void)size;
    return NULL;
}

static void *nullCalloc(void *pool, size_t num, size_t size) {
    (void)pool;
    (void)num;
    (void)size;
    return NULL;
}

static void *nullRealloc(void *pool, void *ptr, size_t size) {
    (void)pool;
    (void)ptr;
    (void)size;
    return NULL;
}

static void *nullAlignedMalloc(void *pool, size_t size, size_t alignment) {
    (void)pool;
    (void)size;
    (void)alignment;
    return NULL;
}

static size_t nullMallocUsableSize(void *pool, void *ptr) {
    (void)ptr;
    (void)pool;
    return 0;
}

static umf_result_t nullFree(void *pool, void *ptr) {
    (void)pool;
    (void)ptr;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t nullGetLastStatus(void *pool) {
    (void)pool;
    return UMF_RESULT_SUCCESS;
}

umf_memory_pool_ops_t UMF_NULL_POOL_OPS = {
    .version = UMF_VERSION_CURRENT,
    .initialize = nullInitialize,
    .finalize = nullFinalize,
    .malloc = nullMalloc,
    .realloc = nullRealloc,
    .calloc = nullCalloc,
    .aligned_malloc = nullAlignedMalloc,
    .malloc_usable_size = nullMallocUsableSize,
    .free = nullFree,
    .get_last_allocation_error = nullGetLastStatus,
};
