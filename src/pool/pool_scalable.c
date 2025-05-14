/*
 *
 * Copyright (C) 2023-2025 Intel Corporation
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

#include <ctl/ctl.h>
#include <memory_pool_internal.h>
#include <umf/memory_pool.h>
#include <umf/memory_pool_ops.h>
#include <umf/memory_provider.h>
#include <umf/pools/pool_scalable.h>

#include "base_alloc_global.h"
#include "libumf.h"
#include "pool_scalable_internal.h"
#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_load_library.h"
#include "utils_log.h"
#include "utils_sanitizers.h"

typedef void *(*raw_alloc_tbb_type)(intptr_t, size_t *);
typedef void (*raw_free_tbb_type)(intptr_t, void *, size_t);

static __TLS umf_result_t TLS_last_allocation_error;
static __TLS umf_result_t TLS_last_free_error;

static const size_t DEFAULT_GRANULARITY = 2 * 1024 * 1024; // 2MB

typedef struct tbb_mem_pool_policy_t {
    raw_alloc_tbb_type pAlloc;
    raw_free_tbb_type pFree;
    size_t granularity;
    int version;
    unsigned fixed_pool : 1, keep_all_memory : 1, reserved : 30;
} tbb_mem_pool_policy_t;

typedef struct umf_scalable_pool_params_t {
    size_t granularity;
    bool keep_all_memory;
} umf_scalable_pool_params_t;

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

static UTIL_ONCE_FLAG tbb_initialized = UTIL_ONCE_FLAG_INIT;
static int tbb_init_result = 0;
static tbb_callbacks_t tbb_callbacks = {0};

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

struct ctl pool_scallable_ctl_root;

static UTIL_ONCE_FLAG ctl_initialized = UTIL_ONCE_FLAG_INIT;

static void init_tbb_callbacks_once(void) {
    const char *lib_name = tbb_symbol[TBB_LIB_NAME];
    tbb_callbacks.lib_handle = utils_open_library(lib_name, 0);
    if (!tbb_callbacks.lib_handle) {
        LOG_ERR("%s required by Scalable Pool not found - install TBB malloc "
                "or make sure it is in the default search paths.",
                lib_name);
        tbb_init_result = -1;
        return;
    }
    *(void **)&tbb_callbacks.pool_malloc = utils_get_symbol_addr(
        tbb_callbacks.lib_handle, tbb_symbol[TBB_POOL_MALLOC], lib_name);
    *(void **)&tbb_callbacks.pool_realloc = utils_get_symbol_addr(
        tbb_callbacks.lib_handle, tbb_symbol[TBB_POOL_REALLOC], lib_name);
    *(void **)&tbb_callbacks.pool_aligned_malloc =
        utils_get_symbol_addr(tbb_callbacks.lib_handle,
                              tbb_symbol[TBB_POOL_ALIGNED_MALLOC], lib_name);
    *(void **)&tbb_callbacks.pool_free = utils_get_symbol_addr(
        tbb_callbacks.lib_handle, tbb_symbol[TBB_POOL_FREE], lib_name);
    *(void **)&tbb_callbacks.pool_create_v1 = utils_get_symbol_addr(
        tbb_callbacks.lib_handle, tbb_symbol[TBB_POOL_CREATE_V1], lib_name);
    *(void **)&tbb_callbacks.pool_destroy = utils_get_symbol_addr(
        tbb_callbacks.lib_handle, tbb_symbol[TBB_POOL_DESTROY], lib_name);
    *(void **)&tbb_callbacks.pool_identify = utils_get_symbol_addr(
        tbb_callbacks.lib_handle, tbb_symbol[TBB_POOL_IDENTIFY], lib_name);
    *(void **)&tbb_callbacks.pool_msize = utils_get_symbol_addr(
        tbb_callbacks.lib_handle, tbb_symbol[TBB_POOL_MSIZE], lib_name);

    if (!tbb_callbacks.pool_malloc || !tbb_callbacks.pool_realloc ||
        !tbb_callbacks.pool_aligned_malloc || !tbb_callbacks.pool_free ||
        !tbb_callbacks.pool_create_v1 || !tbb_callbacks.pool_destroy ||
        !tbb_callbacks.pool_identify) {
        LOG_FATAL("Could not find all TBB symbols in %s", lib_name);
        if (utils_close_library(tbb_callbacks.lib_handle)) {
            LOG_ERR("Could not close %s library", lib_name);
        }
        tbb_init_result = -1;
    }
}

static int init_tbb_callbacks(void) {
    utils_init_once(&tbb_initialized, init_tbb_callbacks_once);
    return tbb_init_result;
}

void fini_tbb_global_state(void) {
    if (tbb_callbacks.lib_handle) {
        if (!utils_close_library(tbb_callbacks.lib_handle)) {
            tbb_callbacks.lib_handle = NULL;
            LOG_DEBUG("TBB library closed");
        } else {
            LOG_ERR("TBB library cannot be unloaded");
        }
    }
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

umf_result_t
umfScalablePoolParamsCreate(umf_scalable_pool_params_handle_t *hParams) {
    libumfInit();
    if (!hParams) {
        LOG_ERR("scalable pool params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_scalable_pool_params_t *params_data =
        umf_ba_global_alloc(sizeof(umf_scalable_pool_params_t));
    if (!params_data) {
        LOG_ERR("cannot allocate memory for scalable pool params");
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    params_data->granularity = DEFAULT_GRANULARITY;
    params_data->keep_all_memory = false;

    *hParams = (umf_scalable_pool_params_handle_t)params_data;

    return UMF_RESULT_SUCCESS;
}

umf_result_t
umfScalablePoolParamsDestroy(umf_scalable_pool_params_handle_t hParams) {
    if (!hParams) {
        LOG_ERR("scalable pool params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_ba_global_free(hParams);

    return UMF_RESULT_SUCCESS;
}

umf_result_t
umfScalablePoolParamsSetGranularity(umf_scalable_pool_params_handle_t hParams,
                                    size_t granularity) {
    if (!hParams) {
        LOG_ERR("scalable pool params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (granularity == 0) {
        LOG_ERR("granularity cannot be 0");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hParams->granularity = granularity;

    return UMF_RESULT_SUCCESS;
}

umf_result_t
umfScalablePoolParamsSetKeepAllMemory(umf_scalable_pool_params_handle_t hParams,
                                      bool keepAllMemory) {
    if (!hParams) {
        LOG_ERR("scalable pool params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hParams->keep_all_memory = keepAllMemory;

    return UMF_RESULT_SUCCESS;
}

static umf_result_t tbb_pool_initialize(umf_memory_provider_handle_t provider,
                                        const void *params, void **pool) {
    tbb_mem_pool_policy_t policy = {.pAlloc = tbb_raw_alloc_wrapper,
                                    .pFree = tbb_raw_free_wrapper,
                                    .granularity = DEFAULT_GRANULARITY,
                                    .version = 1,
                                    .fixed_pool = false,
                                    .keep_all_memory = false,
                                    .reserved = 0};

    if (params) {
        const umf_scalable_pool_params_t *scalable_params = params;
        policy.granularity = scalable_params->granularity;
        policy.keep_all_memory = scalable_params->keep_all_memory;
    }

    tbb_memory_pool_t *pool_data =
        umf_ba_global_alloc(sizeof(tbb_memory_pool_t));
    if (!pool_data) {
        LOG_ERR("cannot allocate memory for metadata");
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    umf_result_t res = UMF_RESULT_SUCCESS;
    int ret = init_tbb_callbacks();
    if (ret != 0) {
        LOG_FATAL("loading TBB symbols failed");
        res = UMF_RESULT_ERROR_DEPENDENCY_UNAVAILABLE;
        goto err_tbb_init;
    }

    pool_data->mem_provider = provider;
    ret = tbb_callbacks.pool_create_v1((intptr_t)pool_data, &policy,
                                       &(pool_data->tbb_pool));
    if (ret != 0 /* TBBMALLOC_OK */) {
        res = UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
        goto err_tbb_init;
    }

    *pool = (void *)pool_data;

    return res;

err_tbb_init:
    umf_ba_global_free(pool_data);
    return res;
}

static void tbb_pool_finalize(void *pool) {
    tbb_memory_pool_t *pool_data = (tbb_memory_pool_t *)pool;
    tbb_callbacks.pool_destroy(pool_data->tbb_pool);
    umf_ba_global_free(pool_data);
}

static void *tbb_malloc(void *pool, size_t size) {
    tbb_memory_pool_t *pool_data = (tbb_memory_pool_t *)pool;
    TLS_last_allocation_error = UMF_RESULT_SUCCESS;
    void *ptr = tbb_callbacks.pool_malloc(pool_data->tbb_pool, size);
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
    void *new_ptr = tbb_callbacks.pool_realloc(pool_data->tbb_pool, ptr, size);
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
    void *ptr =
        tbb_callbacks.pool_aligned_malloc(pool_data->tbb_pool, size, alignment);
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
    if (tbb_callbacks.pool_free(pool_data->tbb_pool, ptr)) {
        return UMF_RESULT_SUCCESS;
    }

    if (TLS_last_free_error != UMF_RESULT_SUCCESS) {
        return TLS_last_free_error;
    }

    return UMF_RESULT_ERROR_UNKNOWN;
}

static size_t tbb_malloc_usable_size(void *pool, const void *ptr) {
    tbb_memory_pool_t *pool_data = (tbb_memory_pool_t *)pool;
    // Remove the 'const' qualifier because the TBB pool_msize function requires a non-const pointer.
    return tbb_callbacks.pool_msize(pool_data->tbb_pool, (void *)ptr);
}

static umf_result_t tbb_get_last_allocation_error(void *pool) {
    (void)pool; // not used
    return TLS_last_allocation_error;
}

static umf_result_t pool_ctl(void *hPool, int operationType, const char *name,
                             void *arg, size_t size,
                             umf_ctl_query_type_t query_type) {
    (void)operationType; // unused
    umf_memory_pool_handle_t pool_provider = (umf_memory_pool_handle_t)hPool;
    utils_init_once(&ctl_initialized, NULL);
    return ctl_query(&pool_scallable_ctl_root, pool_provider->pool_priv,
                     CTL_QUERY_PROGRAMMATIC, name, query_type, arg, size);
}

static const char *scalable_get_name(void *pool) {
    (void)pool; // unused
    return "scalable";
}

static umf_memory_pool_ops_t UMF_SCALABLE_POOL_OPS = {
    .version = UMF_POOL_OPS_VERSION_CURRENT,
    .initialize = tbb_pool_initialize,
    .finalize = tbb_pool_finalize,
    .malloc = tbb_malloc,
    .calloc = tbb_calloc,
    .realloc = tbb_realloc,
    .aligned_malloc = tbb_aligned_malloc,
    .malloc_usable_size = tbb_malloc_usable_size,
    .free = tbb_free,
    .get_last_allocation_error = tbb_get_last_allocation_error,
    .ctl = pool_ctl,
    .get_name = scalable_get_name,
};

const umf_memory_pool_ops_t *umfScalablePoolOps(void) {
    return &UMF_SCALABLE_POOL_OPS;
}
