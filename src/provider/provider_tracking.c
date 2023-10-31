/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "provider_tracking.h"
#include "critnib.h"
#include "../ipc_internal.h"

#include <umf/memory_pool.h>
#include <umf/memory_provider.h>
#include <umf/memory_provider_ops.h>

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
critnib *TRACKER = NULL;
void __attribute__((constructor)) createLibTracker(void) {
    TRACKER = critnib_new();
}
void __attribute__((destructor)) deleteLibTracker(void) {
    critnib_delete(TRACKER);
}

umf_memory_tracker_handle_t umfMemoryTrackerGet(void) {
    return (umf_memory_tracker_handle_t)TRACKER;
}
#endif

typedef struct tracker_value_t {
    umf_memory_pool_handle_t pool;
    size_t size;
} tracker_value_t;

static umf_result_t umfMemoryTrackerAdd(umf_memory_tracker_handle_t hTracker,
                                        umf_memory_pool_handle_t pool,
                                        const void *ptr, size_t size) {
    assert(ptr);

    tracker_value_t *value = (tracker_value_t *)malloc(sizeof(tracker_value_t));
    value->pool = pool;
    value->size = size;

    int ret = critnib_insert((critnib *)hTracker, (uintptr_t)ptr, value, 0);

    if (ret == 0) {
        return UMF_RESULT_SUCCESS;
    }

    free(value);

    if (ret == ENOMEM) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    // This should not happen
    // TODO: add logging here
    return UMF_RESULT_ERROR_UNKNOWN;
}

static umf_result_t umfMemoryTrackerRemove(umf_memory_tracker_handle_t hTracker,
                                           const void *ptr, size_t size) {
    assert(ptr);

    // TODO: there is no support for removing partial ranges (or multiple entries
    // in a single remove call) yet.
    // Every umfMemoryTrackerAdd(..., ptr, ...) should have a corresponding
    // umfMemoryTrackerRemove call with the same ptr value.
    (void)size;

    void *value = critnib_remove((critnib *)hTracker, (uintptr_t)ptr);
    if (!value) {
        // This should not happen
        // TODO: add logging here
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    free(value);

    return UMF_RESULT_SUCCESS;
}

umf_memory_pool_handle_t
umfMemoryTrackerGetPool(umf_memory_tracker_handle_t hTracker, const void *ptr) {
    assert(ptr);

    uintptr_t rkey;
    tracker_value_t *rvalue;
    int found = critnib_find((critnib *)hTracker, (uintptr_t)ptr, FIND_LE,
                             (void *)&rkey, (void **)&rvalue);
    if (!found) {
        return NULL;
    }

    return (rkey + rvalue->size >= (uintptr_t)ptr) ? rvalue->pool : NULL;
}

umf_result_t
umfMemoryTrackerGetAllocInfo(umf_memory_tracker_handle_t hTracker,
                             const void *ptr,
                             umf_alloc_info_t *pAllocInfo) {
    assert(ptr);
    assert(pAllocInfo);

    uintptr_t rkey;
    tracker_value_t *rvalue;
    int found = critnib_find((critnib *)hTracker, (uintptr_t)ptr, FIND_LE,
                             (void *)&rkey, (void **)&rvalue);
    if (!found || (uintptr_t)ptr >= rkey + rvalue->size) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    pAllocInfo->base = (void *)rkey;
    pAllocInfo->size = rvalue->size;
    pAllocInfo->pool = rvalue->pool;

    return UMF_RESULT_SUCCESS;
}

typedef struct ipc_cache_value_t {
    uint64_t size;
    char ipcData[];
} ipc_cache_value_t;

typedef struct umf_tracking_memory_provider_t {
    umf_memory_provider_handle_t hUpstream;
    umf_memory_tracker_handle_t hTracker;
    umf_memory_pool_handle_t pool;
    critnib *ipcCache;
} umf_tracking_memory_provider_t;

typedef struct umf_tracking_memory_provider_t umf_tracking_memory_provider_t;

static umf_result_t trackingAlloc(void *hProvider, size_t size,
                                  size_t alignment, void **ptr) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)hProvider;
    umf_result_t ret = UMF_RESULT_SUCCESS;

    if (!p->hUpstream) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    ret = umfMemoryProviderAlloc(p->hUpstream, size, alignment, ptr);
    if (ret != UMF_RESULT_SUCCESS || !*ptr) {
        return ret;
    }

    ret = umfMemoryTrackerAdd(p->hTracker, p->pool, *ptr, size);
    if (ret != UMF_RESULT_SUCCESS && p->hUpstream) {
        if (umfMemoryProviderFree(p->hUpstream, *ptr, size)) {
            // TODO: LOG
        }
    }

    return ret;
}

static umf_result_t trackingFree(void *hProvider, void *ptr, size_t size) {
    umf_result_t ret;
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)hProvider;

    // umfMemoryTrackerRemove should be called before umfMemoryProviderFree
    // to avoid a race condition. If the order would be different, other thread
    // could allocate the memory at address `ptr` before a call to umfMemoryTrackerRemove
    // resulting in inconsistent state.
    if (ptr) {
        ret = umfMemoryTrackerRemove(p->hTracker, ptr, size);
        if (ret != UMF_RESULT_SUCCESS) {
            return ret;
        }
    }

    void *value = critnib_remove(p->ipcCache, (uintptr_t)ptr);
    if (value) {
        ipc_cache_value_t *cache_value = (ipc_cache_value_t *)value;
        ret = umfMemoryProviderPutIPCHandle(p->hUpstream, cache_value->ipcData);
        assert(ret == UMF_RESULT_SUCCESS);
        free(value);
    }

    ret = umfMemoryProviderFree(p->hUpstream, ptr, size);
    if (ret != UMF_RESULT_SUCCESS) {
        if (umfMemoryTrackerAdd(p->hTracker, p->pool, ptr, size) !=
            UMF_RESULT_SUCCESS) {
            // TODO: LOG
        }
        return ret;
    }

    return ret;
}

static umf_result_t trackingInitialize(void *params, void **ret) {
    umf_tracking_memory_provider_t *provider =
        (umf_tracking_memory_provider_t *)malloc(
            sizeof(umf_tracking_memory_provider_t));
    if (!provider) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    *provider = *((umf_tracking_memory_provider_t *)params);
    *ret = provider;
    return UMF_RESULT_SUCCESS;
}

static void trackingFinalize(void *provider) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    critnib_delete(p->ipcCache);
    free(provider);
}

static void trackingGetLastError(void *provider, const char **msg,
                                 int32_t *pError) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    umfMemoryProviderGetLastNativeError(p->hUpstream, msg, pError);
}

static umf_result_t trackingGetRecommendedPageSize(void *provider, size_t size,
                                                   size_t *pageSize) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    return umfMemoryProviderGetRecommendedPageSize(p->hUpstream, size,
                                                   pageSize);
}

static umf_result_t trackingGetMinPageSize(void *provider, void *ptr,
                                           size_t *pageSize) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    return umfMemoryProviderGetMinPageSize(p->hUpstream, ptr, pageSize);
}

static umf_result_t trackingPurgeLazy(void *provider, void *ptr, size_t size) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    return umfMemoryProviderPurgeLazy(p->hUpstream, ptr, size);
}

static umf_result_t trackingPurgeForce(void *provider, void *ptr, size_t size) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    return umfMemoryProviderPurgeForce(p->hUpstream, ptr, size);
}

static const char *trackingName(void *provider) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    return umfMemoryProviderGetName(p->hUpstream);
}

static umf_result_t trackingGetIpcHandleSize(void *provider,
                                                  size_t *size) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    return umfMemoryProviderGetIPCHandleSize(p->hUpstream, size);
}

static umf_result_t trackingGetIpcHandle(void *provider, const void *ptr,
                                              size_t size, void *ipcData) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    umf_result_t ret = UMF_RESULT_SUCCESS;
    size_t ipcDataSize = 0;
    int cached = 0;
    do {
        void *value = critnib_get(p->ipcCache, (uintptr_t)ptr);
        if (value) { //cache hit
            ipc_cache_value_t *cache_value = (ipc_cache_value_t *)value;
            memcpy(ipcData, cache_value->ipcData, cache_value->size);
            cached = 1;
        } else {
            ret =
                umfMemoryProviderGetIPCHandle(p->hUpstream, ptr, size, ipcData);
            if (ret != UMF_RESULT_SUCCESS) {
                return ret;
            }

            ret = umfMemoryProviderGetIPCHandleSize(p->hUpstream, &ipcDataSize);
            assert(ret == UMF_RESULT_SUCCESS);

            size_t value_size = sizeof(ipc_cache_value_t) + ipcDataSize;
            ipc_cache_value_t *cache_value =
                (ipc_cache_value_t *)malloc(value_size);

            cache_value->size = ipcDataSize;
            memcpy(cache_value->ipcData, ipcData, ipcDataSize);

            int insRes = critnib_insert(p->ipcCache, (uintptr_t)ptr,
                                        (void *)cache_value, 0 /*update*/);
            if (insRes == 0) {
                cached = 1;
            } else {
                // critnib_insert might fail in 2 cases:
                // 1. Another thread created cache entry. So we need to
                //    clean up allocated handle and try to read again from
                //    the cache. Alternative approach could be insert empty
                //    cache_value and only if insert succeed get actual IPC
                //    handle and fill the cache_value structure under the lock.
                //    But this case should be rare enough.
                // 2. critnib failed to allocate memory internally. We need
                //    to cleanup and return corresponding error.
                free(cache_value);
                ret = umfMemoryProviderPutIPCHandle(p->hUpstream, ipcData);
                if (ret != UMF_RESULT_SUCCESS) {
                    return ret;
                }
                if (insRes == ENOMEM) {
                    return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
                }
            }
        }
    } while (!cached);

    return ret;
}

static umf_result_t trackingPutIpcHandle(void *provider, void *ipcData) {
    (void)provider;
    (void)ipcData;
    // We just keep ipcData in the provider->ipcCache.
    // The actual Put is called inside trackingFree
    return UMF_RESULT_SUCCESS;
}

static size_t getDataSizeFromIpcHandle(const void *ipcData) {
    // This is hack to get size of memory pointed by IPC handle.
    // tracking memory provider gets only provider-specific data
    // pointed by ipcData, but the size of allocation tracked
    // by umf_ipc_data_t. We use this trick to get pointer to
    // umf_ipc_data_t data because the ipcData is
    // the Flexible Array Member of umf_ipc_data_t.
    umf_ipc_data_t *ipcUmfData =
        (umf_ipc_data_t *)((uint8_t *)ipcData - sizeof(umf_ipc_data_t));
    return ipcUmfData->size;
}

static umf_result_t trackingOpenIpcHandle(void *provider, void *ipcData,
                                               void **ptr) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    umf_result_t ret = UMF_RESULT_SUCCESS;

    ret = umfMemoryProviderOpenIPCHandle(p->hUpstream, ipcData, ptr);
    if (ret != UMF_RESULT_SUCCESS) {
        return ret;
    }
    size_t bufferSize = getDataSizeFromIpcHandle(ipcData);
    ret = umfMemoryTrackerAdd(p->hTracker, p->pool, *ptr, bufferSize);
    if (ret != UMF_RESULT_SUCCESS && p->hUpstream) {
        if (umfMemoryProviderCloseIPCHandle(p->hUpstream, *ptr)) {
            // TODO: LOG
        }
    }
    return ret;
}

static umf_result_t trackingCloseIpcHandle(void *provider, void *ptr) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    return umfMemoryProviderCloseIPCHandle(p->hUpstream, ptr);
}

umf_memory_provider_ops_t UMF_TRACKING_MEMORY_PROVIDER_OPS = {
    .version = UMF_VERSION_CURRENT,
    .initialize = trackingInitialize,
    .finalize = trackingFinalize,
    .alloc = trackingAlloc,
    .free = trackingFree,
    .get_last_native_error = trackingGetLastError,
    .get_min_page_size = trackingGetMinPageSize,
    .get_recommended_page_size = trackingGetRecommendedPageSize,
    .purge_force = trackingPurgeForce,
    .purge_lazy = trackingPurgeLazy,
    .get_name = trackingName,
    .get_ipc_handle_size = trackingGetIpcHandleSize,
    .get_ipc_handle = trackingGetIpcHandle,
    .put_ipc_handle = trackingPutIpcHandle,
    .open_ipc_handle = trackingOpenIpcHandle,
    .close_ipc_handle = trackingCloseIpcHandle};

umf_result_t umfTrackingMemoryProviderCreate(
    umf_memory_provider_handle_t hUpstream, umf_memory_pool_handle_t hPool,
    umf_memory_provider_handle_t *hTrackingProvider) {
    umf_tracking_memory_provider_t params;
    params.hUpstream = hUpstream;
    params.hTracker = umfMemoryTrackerGet();
    params.pool = hPool;
    params.ipcCache = critnib_new();
    if (!params.ipcCache) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    return umfMemoryProviderCreate(&UMF_TRACKING_MEMORY_PROVIDER_OPS, &params,
                                   hTrackingProvider);
}

void umfTrackingMemoryProviderGetUpstreamProvider(
    umf_memory_provider_handle_t hTrackingProvider,
    umf_memory_provider_handle_t *hUpstream) {
    assert(hUpstream);
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)hTrackingProvider;
    *hUpstream = p->hUpstream;
}
