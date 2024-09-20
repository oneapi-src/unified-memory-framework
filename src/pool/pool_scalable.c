/*
 *
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <umf/memory_pool.h>
#include <umf/memory_pool_ops.h>
#include <umf/memory_provider.h>
#include <umf/pools/pool_scalable.h>

#include "base_alloc_global.h"
#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_load_library.h"
#include "utils_log.h"
#include "utils_sanitizers.h"

typedef void *(*raw_alloc_tbb_type)(intptr_t, size_t *);
typedef void (*raw_free_tbb_type)(intptr_t, void *, size_t);

static __TLS umf_result_t TLS_last_allocation_error;
static __TLS umf_result_t TLS_last_free_error;

typedef struct tbb_mem_pool_policy_t {
    raw_alloc_tbb_type pAlloc;
    raw_free_tbb_type pFree;
    size_t granularity;
    int version;
    unsigned fixed_pool : 1, keep_all_memory : 1, reserved : 30;
} tbb_mem_pool_policy_t;

typedef struct tbb_callbacks_t {
    void *(*pool_malloc)(void *, size_t);
    void *(*pool_realloc)(void *, void *, size_t);
    void *(*pool_aligned_malloc)(void *, size_t, size_t);
    bool (*pool_free)(void *, void *);
    int (*pool_create_v1)(intptr_t, const struct tbb_mem_pool_policy_t *,
                          void **);
    bool (*pool_destroy)(void *);
    void *(*pool_identify)(void *object);
    size_t (*pool_msize)(void *, void *);
#ifdef _WIN32
    HMODULE lib_handle;
#else
    void *lib_handle;
#endif
} tbb_callbacks_t;

typedef struct tbb_memory_pool_t {
    umf_memory_provider_handle_t mem_provider;
    void *tbb_pool;
    tbb_callbacks_t tbb_callbacks;
} tbb_memory_pool_t;

typedef enum tbb_enums_t {
    TBB_LIB_NAME = 0,
    TBB_POOL_MALLOC,
    TBB_POOL_REALLOC,
    TBB_POOL_ALIGNED_MALLOC,
    TBB_POOL_FREE,
    TBB_POOL_CREATE_V1,
    TBB_POOL_DESTROY,
    TBB_POOL_IDENTIFY,
    TBB_POOL_MSIZE,
    TBB_POOL_SYMBOLS_MAX // it has to be the last one
} tbb_enums_t;

static const char *tbb_symbol[TBB_POOL_SYMBOLS_MAX] = {
#ifdef _WIN32
    // symbols copied from oneTBB/src/tbbmalloc/def/win64-tbbmalloc.def
    "tbbmalloc.dll",
    "?pool_malloc@rml@@YAPEAXPEAVMemoryPool@1@_K@Z",
    "?pool_realloc@rml@@YAPEAXPEAVMemoryPool@1@PEAX_K@Z",
    "?pool_aligned_malloc@rml@@YAPEAXPEAVMemoryPool@1@_K1@Z",
    "?pool_free@rml@@YA_NPEAVMemoryPool@1@PEAX@Z",
    ("?pool_create_v1@rml@@YA?AW4MemPoolError@1@_JPEBUMemPoolPolicy@1@"
     "PEAPEAVMemoryPool@1@@Z"),
    "?pool_destroy@rml@@YA_NPEAVMemoryPool@1@@Z",
    "?pool_identify@rml@@YAPEAVMemoryPool@1@PEAX@Z",
    "?pool_msize@rml@@YA_KPEAVMemoryPool@1@PEAX@Z"
#else
    // symbols copied from oneTBB/src/tbbmalloc/def/lin64-tbbmalloc.def
    "libtbbmalloc.so.2",
    "_ZN3rml11pool_mallocEPNS_10MemoryPoolEm",
    "_ZN3rml12pool_reallocEPNS_10MemoryPoolEPvm",
    "_ZN3rml19pool_aligned_mallocEPNS_10MemoryPoolEmm",
    "_ZN3rml9pool_freeEPNS_10MemoryPoolEPv",
    "_ZN3rml14pool_create_v1ElPKNS_13MemPoolPolicyEPPNS_10MemoryPoolE",
    "_ZN3rml12pool_destroyEPNS_10MemoryPoolE",
    "_ZN3rml13pool_identifyEPv",
    "_ZN3rml10pool_msizeEPNS_10MemoryPoolEPv"
#endif
};

static int init_tbb_callbacks(tbb_callbacks_t *tbb_callbacks) {
    assert(tbb_callbacks);

    const char *lib_name = tbb_symbol[TBB_LIB_NAME];
    tbb_callbacks->lib_handle = utils_open_library(lib_name, 0);
    if (!tbb_callbacks->lib_handle) {
        LOG_ERR("%s required by Scalable Pool not found - install TBB malloc "
                "or make sure it is in the default search paths.",
                lib_name);
        return -1;
    }

    *(void **)&tbb_callbacks->pool_malloc = utils_get_symbol_addr(
        tbb_callbacks->lib_handle, tbb_symbol[TBB_POOL_MALLOC], lib_name);
    *(void **)&tbb_callbacks->pool_realloc = utils_get_symbol_addr(
        tbb_callbacks->lib_handle, tbb_symbol[TBB_POOL_REALLOC], lib_name);
    *(void **)&tbb_callbacks->pool_aligned_malloc =
        utils_get_symbol_addr(tbb_callbacks->lib_handle,
                              tbb_symbol[TBB_POOL_ALIGNED_MALLOC], lib_name);
    *(void **)&tbb_callbacks->pool_free = utils_get_symbol_addr(
        tbb_callbacks->lib_handle, tbb_symbol[TBB_POOL_FREE], lib_name);
    *(void **)&tbb_callbacks->pool_create_v1 = utils_get_symbol_addr(
        tbb_callbacks->lib_handle, tbb_symbol[TBB_POOL_CREATE_V1], lib_name);
    *(void **)&tbb_callbacks->pool_destroy = utils_get_symbol_addr(
        tbb_callbacks->lib_handle, tbb_symbol[TBB_POOL_DESTROY], lib_name);
    *(void **)&tbb_callbacks->pool_identify = utils_get_symbol_addr(
        tbb_callbacks->lib_handle, tbb_symbol[TBB_POOL_IDENTIFY], lib_name);
    *(void **)&tbb_callbacks->pool_msize = utils_get_symbol_addr(
        tbb_callbacks->lib_handle, tbb_symbol[TBB_POOL_MSIZE], lib_name);

    if (!tbb_callbacks->pool_malloc || !tbb_callbacks->pool_realloc ||
        !tbb_callbacks->pool_aligned_malloc || !tbb_callbacks->pool_free ||
        !tbb_callbacks->pool_create_v1 || !tbb_callbacks->pool_destroy ||
        !tbb_callbacks->pool_identify) {
        LOG_ERR("Could not find symbols in %s", lib_name);
        utils_close_library(tbb_callbacks->lib_handle);
        return -1;
    }

    return 0;
}

static void *tbb_raw_alloc_wrapper(intptr_t pool_id, size_t *raw_bytes) {
    void *resPtr;
    tbb_memory_pool_t *pool = (tbb_memory_pool_t *)pool_id;
    umf_result_t ret =
        umfMemoryProviderAlloc(pool->mem_provider, *raw_bytes, 0, &resPtr);
    if (ret != UMF_RESULT_SUCCESS) {
        TLS_last_allocation_error = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        return NULL;
    }

    return resPtr;
}

static void tbb_raw_free_wrapper(intptr_t pool_id, void *ptr, size_t bytes) {
    tbb_memory_pool_t *pool = (tbb_memory_pool_t *)pool_id;
    umf_result_t ret = umfMemoryProviderFree(pool->mem_provider, ptr, bytes);
    if (ret != UMF_RESULT_SUCCESS) {
        TLS_last_free_error = ret;
        LOG_ERR("Memory provider failed to free memory, addr = %p, size = %zu",
                ptr, bytes);
    }
}

static umf_result_t tbb_pool_initialize(umf_memory_provider_handle_t provider,
                                        void *params, void **pool) {
    (void)params; // unused

    const size_t GRANULARITY = 2 * 1024 * 1024;
    tbb_mem_pool_policy_t policy = {.pAlloc = tbb_raw_alloc_wrapper,
                                    .pFree = tbb_raw_free_wrapper,
                                    .granularity = GRANULARITY,
                                    .version = 1,
                                    .fixed_pool = false,
                                    .keep_all_memory = false,
                                    .reserved = 0};

    tbb_memory_pool_t *pool_data =
        umf_ba_global_alloc(sizeof(tbb_memory_pool_t));
    if (!pool_data) {
        LOG_ERR("cannot allocate memory for metadata");
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    int ret = init_tbb_callbacks(&pool_data->tbb_callbacks);
    if (ret != 0) {
        LOG_ERR("loading TBB symbols failed");
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    pool_data->mem_provider = provider;
    ret = pool_data->tbb_callbacks.pool_create_v1((intptr_t)pool_data, &policy,
                                                  &(pool_data->tbb_pool));
    if (ret != 0 /* TBBMALLOC_OK */) {
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    *pool = (void *)pool_data;

    return UMF_RESULT_SUCCESS;
}

static void tbb_pool_finalize(void *pool) {
    tbb_memory_pool_t *pool_data = (tbb_memory_pool_t *)pool;
    pool_data->tbb_callbacks.pool_destroy(pool_data->tbb_pool);
    utils_close_library(pool_data->tbb_callbacks.lib_handle);
    umf_ba_global_free(pool_data);
}

static void *tbb_malloc(void *pool, size_t size) {
    tbb_memory_pool_t *pool_data = (tbb_memory_pool_t *)pool;
    TLS_last_allocation_error = UMF_RESULT_SUCCESS;
    void *ptr = pool_data->tbb_callbacks.pool_malloc(pool_data->tbb_pool, size);
    if (ptr == NULL) {
        if (TLS_last_allocation_error == UMF_RESULT_SUCCESS) {
            TLS_last_allocation_error = UMF_RESULT_ERROR_UNKNOWN;
        }
        return NULL;
    }
    utils_annotate_acquire(pool);
    return ptr;
}

static void *tbb_calloc(void *pool, size_t num, size_t size) {
    assert(pool);
    size_t csize = num * size;
    void *ptr = tbb_malloc(pool, csize);
    if (ptr == NULL) {
        // TLS_last_allocation_error is set by tbb_malloc()
        return NULL;
    }

    memset(ptr, 0, csize);
    return ptr;
}

static void *tbb_realloc(void *pool, void *ptr, size_t size) {
    tbb_memory_pool_t *pool_data = (tbb_memory_pool_t *)pool;
    TLS_last_allocation_error = UMF_RESULT_SUCCESS;
    void *new_ptr =
        pool_data->tbb_callbacks.pool_realloc(pool_data->tbb_pool, ptr, size);
    if (new_ptr == NULL) {
        if (TLS_last_allocation_error == UMF_RESULT_SUCCESS) {
            TLS_last_allocation_error = UMF_RESULT_ERROR_UNKNOWN;
        }
        return NULL;
    }
    utils_annotate_acquire(pool);
    return new_ptr;
}

static void *tbb_aligned_malloc(void *pool, size_t size, size_t alignment) {
    tbb_memory_pool_t *pool_data = (tbb_memory_pool_t *)pool;
    TLS_last_allocation_error = UMF_RESULT_SUCCESS;
    void *ptr = pool_data->tbb_callbacks.pool_aligned_malloc(
        pool_data->tbb_pool, size, alignment);
    if (ptr == NULL) {
        if (TLS_last_allocation_error == UMF_RESULT_SUCCESS) {
            TLS_last_allocation_error = UMF_RESULT_ERROR_UNKNOWN;
        }
        return NULL;
    }
    utils_annotate_acquire(pool);
    return ptr;
}

static umf_result_t tbb_free(void *pool, void *ptr) {
    if (ptr == NULL) {
        return UMF_RESULT_SUCCESS;
    }

    TLS_last_free_error = UMF_RESULT_SUCCESS;

    // Establishes happens-before order with tbb_*alloc functions.
    // Makes sure that writes to the memory pointed to by 'ptr'
    // are not reported as data races whenever 'ptr' reused by
    // other threads.
    utils_annotate_release(pool);

    tbb_memory_pool_t *pool_data = (tbb_memory_pool_t *)pool;
    if (pool_data->tbb_callbacks.pool_free(pool_data->tbb_pool, ptr)) {
        return UMF_RESULT_SUCCESS;
    }

    if (TLS_last_free_error != UMF_RESULT_SUCCESS) {
        return TLS_last_free_error;
    }

    return UMF_RESULT_ERROR_UNKNOWN;
}

static size_t tbb_malloc_usable_size(void *pool, void *ptr) {
    tbb_memory_pool_t *pool_data = (tbb_memory_pool_t *)pool;
    return pool_data->tbb_callbacks.pool_msize(pool_data->tbb_pool, ptr);
}

static umf_result_t tbb_get_last_allocation_error(void *pool) {
    (void)pool; // not used
    return TLS_last_allocation_error;
}

static umf_memory_pool_ops_t UMF_SCALABLE_POOL_OPS = {
    .version = UMF_VERSION_CURRENT,
    .initialize = tbb_pool_initialize,
    .finalize = tbb_pool_finalize,
    .malloc = tbb_malloc,
    .calloc = tbb_calloc,
    .realloc = tbb_realloc,
    .aligned_malloc = tbb_aligned_malloc,
    .malloc_usable_size = tbb_malloc_usable_size,
    .free = tbb_free,
    .get_last_allocation_error = tbb_get_last_allocation_error};

umf_memory_pool_ops_t *umfScalablePoolOps(void) {
    return &UMF_SCALABLE_POOL_OPS;
}
