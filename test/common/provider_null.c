// Copyright (C) 2023 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <assert.h>
#include <stdlib.h>

#include <umf/memory_provider_ops.h>
#include "provider_null.h"

static enum umf_result_t nullInitialize(void *params, void **pool) {
    (void)params;
    *pool = NULL;
    return UMF_RESULT_SUCCESS;
}

static void nullFinalize(void *pool) { (void)pool; }

static enum umf_result_t nullAlloc(void *provider, size_t size,
                                   size_t alignment, void **ptr) {
    (void)provider;
    (void)size;
    (void)alignment;
    *ptr = NULL;
    return UMF_RESULT_SUCCESS;
}

static enum umf_result_t nullFree(void *provider, void *ptr, size_t size) {
    (void)provider;
    (void)ptr;
    (void)size;
    return UMF_RESULT_SUCCESS;
}

static void nullGetLastError(void *provider, const char **ppMsg,
                             int32_t *pError) {
    (void)provider;
    (void)ppMsg;
    (void)pError;
}

static enum umf_result_t nullGetRecommendedPageSize(void *provider, size_t size,
                                                    size_t *pageSize) {
    (void)provider;
    (void)size;
    (void)pageSize;
    return UMF_RESULT_SUCCESS;
}

static enum umf_result_t nullGetPageSize(void *provider, void *ptr,

                                         size_t *pageSize) {
    (void)provider;
    (void)ptr;
    (void)pageSize;
    return UMF_RESULT_SUCCESS;
}

static enum umf_result_t nullPurgeLazy(void *provider, void *ptr, size_t size) {
    (void)provider;
    (void)ptr;
    (void)size;
    return UMF_RESULT_SUCCESS;
}

static enum umf_result_t nullPurgeForce(void *provider, void *ptr,
                                        size_t size) {
    (void)provider;
    (void)ptr;
    (void)size;
    return UMF_RESULT_SUCCESS;
}

static const char *nullName(void *provider) {
    (void)provider;
    return "null";
}

struct umf_memory_provider_ops_t UMF_NULL_PROVIDER_OPS = {
    .version = UMF_VERSION_CURRENT,
    .initialize = nullInitialize,
    .finalize = nullFinalize,
    .alloc = nullAlloc,
    .free = nullFree,
    .get_last_native_error = nullGetLastError,
    .get_recommended_page_size = nullGetRecommendedPageSize,
    .get_min_page_size = nullGetPageSize,
    .purge_lazy = nullPurgeLazy,
    .purge_force = nullPurgeForce,
    .get_name = nullName,
};
