/*
 *
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "provider_tracking.h"
#include "base_alloc_global.h"
#include "critnib.h"
#include "ipc_internal.h"
#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_log.h"

#include <umf/memory_pool.h>
#include <umf/memory_provider.h>
#include <umf/memory_provider_ops.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct tracker_value_t {
    umf_memory_pool_handle_t pool;
    size_t size;
} tracker_value_t;

static umf_result_t umfMemoryTrackerAdd(umf_memory_tracker_handle_t hTracker,
                                        umf_memory_pool_handle_t pool,
                                        const void *ptr, size_t size) {
    assert(ptr);

    tracker_value_t *value = umf_ba_alloc(hTracker->tracker_allocator);
    if (value == NULL) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    value->pool = pool;
    value->size = size;

    int ret = critnib_insert(hTracker->map, (uintptr_t)ptr, value, 0);

    if (ret == 0) {
        return UMF_RESULT_SUCCESS;
    }

    umf_ba_free(hTracker->tracker_allocator, value);

    if (ret == ENOMEM) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    LOG_ERR("umfMemoryTrackerAdd: Unknown Error %d", ret);
    return UMF_RESULT_ERROR_UNKNOWN;
}

static umf_result_t umfMemoryTrackerRemove(umf_memory_tracker_handle_t hTracker,
                                           const void *ptr, size_t *size) {
    assert(ptr);

    // TODO: there is no support for removing partial ranges (or multiple entries
    // in a single remove call) yet.
    // Every umfMemoryTrackerAdd(..., ptr, ...) should have a corresponding
    // umfMemoryTrackerRemove call with the same ptr value.

    tracker_value_t *value = critnib_remove(hTracker->map, (uintptr_t)ptr);
    if (!value) {
        LOG_ERR("umfMemoryTrackerRemove: pointer %p not found in the map", ptr);
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    if (size) {
        *size = value->size;
    }

    umf_ba_free(hTracker->tracker_allocator, value);

    return UMF_RESULT_SUCCESS;
}

umf_memory_pool_handle_t umfMemoryTrackerGetPool(const void *ptr) {
    umf_alloc_info_t allocInfo = {0};
    umf_result_t ret = umfMemoryTrackerGetAllocInfo(ptr, &allocInfo);
    if (ret != UMF_RESULT_SUCCESS) {
        return NULL;
    }

    return allocInfo.pool;
}

umf_result_t umfMemoryTrackerGetAllocInfo(const void *ptr,
                                          umf_alloc_info_t *pAllocInfo) {
    assert(ptr);
    assert(pAllocInfo);

    if (TRACKER == NULL) {
        LOG_ERR("tracker is not created");
        return UMF_RESULT_ERROR_NOT_SUPPORTED;
    }

    if (TRACKER->map == NULL) {
        LOG_ERR("tracker's map is not created");
        return UMF_RESULT_ERROR_NOT_SUPPORTED;
    }

    uintptr_t rkey;
    tracker_value_t *rvalue;
    int found = critnib_find(TRACKER->map, (uintptr_t)ptr, FIND_LE,
                             (void *)&rkey, (void **)&rvalue);
    if (!found || (uintptr_t)ptr >= rkey + rvalue->size) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    pAllocInfo->base = (void *)rkey;
    pAllocInfo->baseSize = rvalue->size;
    pAllocInfo->pool = rvalue->pool;

    return UMF_RESULT_SUCCESS;
}

// Cache entry structure to store provider-specific IPC data.
// providerIpcData is a Flexible Array Member because its size varies
// depending on the provider.
typedef struct ipc_cache_value_t {
    uint64_t ipcDataSize;
    char providerIpcData[];
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

    assert(p->hUpstream);

    ret = umfMemoryProviderAlloc(p->hUpstream, size, alignment, ptr);
    if (ret != UMF_RESULT_SUCCESS || !*ptr) {
        return ret;
    }

    umf_result_t ret2 = umfMemoryTrackerAdd(p->hTracker, p->pool, *ptr, size);
    if (ret2 != UMF_RESULT_SUCCESS) {
        LOG_ERR("umfMemoryTrackerAdd failed: %d", ret2);
    }

    return ret;
}

static umf_result_t trackingAllocationSplit(void *hProvider, void *ptr,
                                            size_t totalSize,
                                            size_t firstSize) {
    umf_result_t ret = UMF_RESULT_ERROR_UNKNOWN;
    umf_tracking_memory_provider_t *provider =
        (umf_tracking_memory_provider_t *)hProvider;

    tracker_value_t *splitValue =
        umf_ba_alloc(provider->hTracker->tracker_allocator);
    if (!splitValue) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    splitValue->pool = provider->pool;
    splitValue->size = firstSize;

    int r = util_mutex_lock(&provider->hTracker->splitMergeMutex);
    if (r) {
        goto err_lock;
    }

    tracker_value_t *value =
        (tracker_value_t *)critnib_get(provider->hTracker->map, (uintptr_t)ptr);
    if (!value) {
        LOG_ERR("tracking split: no such value");
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err;
    }
    if (value->size != totalSize) {
        LOG_ERR("tracking split: %zu != %zu", value->size, totalSize);
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err;
    }

    ret = umfMemoryProviderAllocationSplit(provider->hUpstream, ptr, totalSize,
                                           firstSize);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("tracking split: umfMemoryProviderAllocationSplit failed");
        goto err;
    }

    void *highPtr = (void *)(((uintptr_t)ptr) + firstSize);
    size_t secondSize = totalSize - firstSize;

    // We'll have a duplicate entry for the range [highPtr, highValue->size] but this is fine,
    // the value is the same anyway and we forbid removing that range concurrently
    ret = umfMemoryTrackerAdd(provider->hTracker, provider->pool, highPtr,
                              secondSize);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("tracking split: umfMemoryTrackerAdd failed");
        // TODO: what now? should we rollback the split? This can only happen due to ENOMEM
        // so it's unlikely but probably the best solution would be to try to preallocate everything
        // (value and critnib nodes) before calling umfMemoryProviderAllocationSplit.
        goto err;
    }

    int cret = critnib_insert(provider->hTracker->map, (uintptr_t)ptr,
                              (void *)splitValue, 1 /* update */);
    // this cannot fail since we know the element exists (nothing to allocate)
    assert(cret == 0);
    (void)cret;

    // free the original value
    umf_ba_free(provider->hTracker->tracker_allocator, value);
    util_mutex_unlock(&provider->hTracker->splitMergeMutex);

    return UMF_RESULT_SUCCESS;

err:
    util_mutex_unlock(&provider->hTracker->splitMergeMutex);
err_lock:
    umf_ba_free(provider->hTracker->tracker_allocator, splitValue);
    return ret;
}

static umf_result_t trackingAllocationMerge(void *hProvider, void *lowPtr,
                                            void *highPtr, size_t totalSize) {
    umf_result_t ret = UMF_RESULT_ERROR_UNKNOWN;
    umf_tracking_memory_provider_t *provider =
        (umf_tracking_memory_provider_t *)hProvider;

    tracker_value_t *mergedValue =
        umf_ba_alloc(provider->hTracker->tracker_allocator);

    if (!mergedValue) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    mergedValue->pool = provider->pool;
    mergedValue->size = totalSize;

    int r = util_mutex_lock(&provider->hTracker->splitMergeMutex);
    if (r) {
        goto err_lock;
    }

    tracker_value_t *lowValue = (tracker_value_t *)critnib_get(
        provider->hTracker->map, (uintptr_t)lowPtr);
    if (!lowValue) {
        LOG_ERR("tracking merge: no left value");
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err;
    }
    tracker_value_t *highValue = (tracker_value_t *)critnib_get(
        provider->hTracker->map, (uintptr_t)highPtr);
    if (!highValue) {
        LOG_ERR("tracking merge: no right value");
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err;
    }
    if (lowValue->pool != highValue->pool) {
        LOG_ERR("tracking merge: pool mismatch");
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err;
    }
    if (lowValue->size + highValue->size != totalSize) {
        LOG_ERR("tracking merge: lowValue->size + highValue->size != "
                "totalSize");
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err;
    }

    ret = umfMemoryProviderAllocationMerge(provider->hUpstream, lowPtr, highPtr,
                                           totalSize);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("tracking merge: umfMemoryProviderAllocationMerge failed");
        goto err;
    }

    // We'll have a duplicate entry for the range [highPtr, highValue->size] but this is fine,
    // the value is the same anyway and we forbid removing that range concurrently
    int cret = critnib_insert(provider->hTracker->map, (uintptr_t)lowPtr,
                              (void *)mergedValue, 1 /* update */);
    // this cannot fail since we know the element exists (nothing to allocate)
    assert(cret == 0);
    (void)cret;

    // free old value that we just replaced with mergedValue
    umf_ba_free(provider->hTracker->tracker_allocator, lowValue);

    void *erasedhighValue =
        critnib_remove(provider->hTracker->map, (uintptr_t)highPtr);
    assert(erasedhighValue == highValue);

    umf_ba_free(provider->hTracker->tracker_allocator, erasedhighValue);

    util_mutex_unlock(&provider->hTracker->splitMergeMutex);

    return UMF_RESULT_SUCCESS;

err:
    util_mutex_unlock(&provider->hTracker->splitMergeMutex);
err_lock:
    umf_ba_free(provider->hTracker->tracker_allocator, mergedValue);
    return ret;
}

static umf_result_t trackingFree(void *hProvider, void *ptr, size_t size) {
    umf_result_t ret;
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)hProvider;
    size_t saved_size = 0;

    // umfMemoryTrackerRemove should be called before umfMemoryProviderFree
    // to avoid a race condition. If the order would be different, other thread
    // could allocate the memory at address `ptr` before a call to umfMemoryTrackerRemove
    // resulting in inconsistent state.
    if (ptr) {
        ret = umfMemoryTrackerRemove(p->hTracker, ptr, &saved_size);
        if (ret != UMF_RESULT_SUCCESS) {
            // DO NOT return an error here, because the tracking provider
            // cannot change behaviour of the upstream provider.
            // TODO: LOG
        }
    }

    void *value = critnib_remove(p->ipcCache, (uintptr_t)ptr);
    if (value) {
        ipc_cache_value_t *cache_value = (ipc_cache_value_t *)value;
        ret = umfMemoryProviderPutIPCHandle(p->hUpstream,
                                            cache_value->providerIpcData);
        if (ret != UMF_RESULT_SUCCESS) {
            LOG_ERR("tracking free: failed to put IPC handle");
        }
        umf_ba_global_free(value);
    }

    // umfMemoryProviderFree() should not be called with size == 0,
    // so use the size saved in the tracking provider.
    if (size == 0) {
        size = saved_size;
    }
    if (saved_size) {
        assert(size == saved_size);
    }

    ret = umfMemoryProviderFree(p->hUpstream, ptr, size);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("tracking free: umfMemoryProviderFree failed");
        if (umfMemoryTrackerAdd(p->hTracker, p->pool, ptr, size) !=
            UMF_RESULT_SUCCESS) {
            LOG_ERR("tracking free: umfMemoryTrackerAdd failed");
        }
        return ret;
    }

    return ret;
}

static umf_result_t trackingInitialize(void *params, void **ret) {
    umf_tracking_memory_provider_t *provider =
        umf_ba_global_alloc(sizeof(umf_tracking_memory_provider_t));
    if (!provider) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    *provider = *((umf_tracking_memory_provider_t *)params);
    if (provider->hUpstream == NULL || provider->hTracker == NULL ||
        provider->pool == NULL || provider->ipcCache == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *ret = provider;
    return UMF_RESULT_SUCCESS;
}

#ifndef NDEBUG
static void check_if_tracker_is_empty(umf_memory_tracker_handle_t hTracker,
                                      umf_memory_pool_handle_t pool) {
    uintptr_t rkey;
    void *rvalue;
    size_t n_items = 0;
    uintptr_t last_key = 0;

    while (1 == critnib_find((critnib *)hTracker->map, last_key, FIND_G, &rkey,
                             &rvalue)) {
        tracker_value_t *value = (tracker_value_t *)rvalue;
        if (value->pool == pool || pool == NULL) {
            n_items++;
        }

        last_key = rkey;
    }

    if (n_items) {
        // Do not assert if we are running in the proxy library,
        // because it may need those resources till
        // the very end of exiting the application.
        if (!util_is_running_in_proxy_lib()) {
            if (pool) {
                LOG_ERR("tracking provider of pool %p is not empty! "
                        "(%zu items left)",
                        (void *)pool, n_items);
            } else {
                LOG_ERR("tracking provider is not empty! (%zu items "
                        "left)",
                        n_items);
            }
            assert(n_items == 0);
        }
    }
}
#endif /* NDEBUG */

static void trackingFinalize(void *provider) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    critnib_delete(p->ipcCache);
#ifndef NDEBUG
    check_if_tracker_is_empty(p->hTracker, p->pool);
#endif /* NDEBUG */

    umf_ba_global_free(provider);
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

static umf_result_t trackingGetIpcHandleSize(void *provider, size_t *size) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    return umfMemoryProviderGetIPCHandleSize(p->hUpstream, size);
}

static umf_result_t trackingGetIpcHandle(void *provider, const void *ptr,
                                         size_t size, void *providerIpcData) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    umf_result_t ret = UMF_RESULT_SUCCESS;
    size_t ipcDataSize = 0;
    int cached = 0;
    do {
        void *value = critnib_get(p->ipcCache, (uintptr_t)ptr);
        if (value) { //cache hit
            ipc_cache_value_t *cache_value = (ipc_cache_value_t *)value;
            memcpy(providerIpcData, cache_value->providerIpcData,
                   cache_value->ipcDataSize);
            cached = 1;
        } else {
            ret = umfMemoryProviderGetIPCHandle(p->hUpstream, ptr, size,
                                                providerIpcData);
            if (ret != UMF_RESULT_SUCCESS) {
                LOG_ERR("tracking get ipc handle: "
                        "umfMemoryProviderGetIPCHandle failed");
                return ret;
            }

            ret = umfMemoryProviderGetIPCHandleSize(p->hUpstream, &ipcDataSize);
            if (ret != UMF_RESULT_SUCCESS) {
                LOG_ERR("tracking get ipc handle: "
                        "umfMemoryProviderGetIPCHandleSize failed");
                ret = umfMemoryProviderPutIPCHandle(p->hUpstream,
                                                    providerIpcData);
                if (ret != UMF_RESULT_SUCCESS) {
                    LOG_ERR("tracking get ipc handle: "
                            "umfMemoryProviderPutIPCHandle failed");
                }
                return ret;
            }

            size_t value_size = sizeof(ipc_cache_value_t) + ipcDataSize;
            ipc_cache_value_t *cache_value = umf_ba_global_alloc(value_size);
            if (!cache_value) {
                LOG_ERR(
                    "tracking get ipc handle: failed to allocate cache_value");
                ret = umfMemoryProviderPutIPCHandle(p->hUpstream,
                                                    providerIpcData);
                if (ret != UMF_RESULT_SUCCESS) {
                    LOG_ERR("tracking get ipc handle: "
                            "umfMemoryProviderPutIPCHandle failed");
                }
                return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
            }

            cache_value->ipcDataSize = ipcDataSize;
            memcpy(cache_value->providerIpcData, providerIpcData, ipcDataSize);

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
                umf_ba_global_free(cache_value);
                ret = umfMemoryProviderPutIPCHandle(p->hUpstream,
                                                    providerIpcData);
                if (ret != UMF_RESULT_SUCCESS) {
                    LOG_ERR("tracking get ipc handle: "
                            "umfMemoryProviderPutIPCHandle failed");
                    return ret;
                }
                if (insRes == ENOMEM) {
                    LOG_ERR(
                        "tracking get ipc handle: insert to IPC cache failed");
                    return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
                }
            }
        }
    } while (!cached);

    return ret;
}

static umf_result_t trackingPutIpcHandle(void *provider,
                                         void *providerIpcData) {
    (void)provider;
    (void)providerIpcData;
    // We just keep providerIpcData in the provider->ipcCache.
    // The actual Put is called inside trackingFree
    return UMF_RESULT_SUCCESS;
}

static size_t getDataSizeFromIpcHandle(const void *providerIpcData) {
    // This is hack to get size of memory pointed by IPC handle.
    // tracking memory provider gets only provider-specific data
    // pointed by providerIpcData, but the size of allocation tracked
    // by umf_ipc_data_t. We use this trick to get pointer to
    // umf_ipc_data_t data because the providerIpcData is
    // the Flexible Array Member of umf_ipc_data_t.
    umf_ipc_data_t *ipcUmfData =
        (umf_ipc_data_t *)((uint8_t *)providerIpcData - sizeof(umf_ipc_data_t));
    return ipcUmfData->baseSize;
}

static umf_result_t trackingOpenIpcHandle(void *provider, void *providerIpcData,
                                          void **ptr) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    umf_result_t ret = UMF_RESULT_SUCCESS;

    assert(p->hUpstream);

    ret = umfMemoryProviderOpenIPCHandle(p->hUpstream, providerIpcData, ptr);
    if (ret != UMF_RESULT_SUCCESS) {
        return ret;
    }
    size_t bufferSize = getDataSizeFromIpcHandle(providerIpcData);
    ret = umfMemoryTrackerAdd(p->hTracker, p->pool, *ptr, bufferSize);
    if (ret != UMF_RESULT_SUCCESS) {
        if (umfMemoryProviderCloseIPCHandle(p->hUpstream, *ptr, bufferSize)) {
            // TODO: LOG
        }
    }
    return ret;
}

static umf_result_t trackingCloseIpcHandle(void *provider, void *ptr,
                                           size_t size) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;

    // umfMemoryTrackerRemove should be called before umfMemoryProviderFree
    // to avoid a race condition. If the order would be different, other thread
    // could allocate the memory at address `ptr` before a call to umfMemoryTrackerRemove
    // resulting in inconsistent state.
    if (ptr) {
        umf_result_t ret = umfMemoryTrackerRemove(p->hTracker, ptr, NULL);
        if (ret != UMF_RESULT_SUCCESS) {
            // DO NOT return an error here, because the tracking provider
            // cannot change behaviour of the upstream provider.
            LOG_ERR("tracking free: umfMemoryTrackerRemove failed");
        }
    }
    return umfMemoryProviderCloseIPCHandle(p->hUpstream, ptr, size);
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
    .get_name = trackingName,
    .ext.purge_force = trackingPurgeForce,
    .ext.purge_lazy = trackingPurgeLazy,
    .ext.allocation_split = trackingAllocationSplit,
    .ext.allocation_merge = trackingAllocationMerge,
    .ipc.get_ipc_handle_size = trackingGetIpcHandleSize,
    .ipc.get_ipc_handle = trackingGetIpcHandle,
    .ipc.put_ipc_handle = trackingPutIpcHandle,
    .ipc.open_ipc_handle = trackingOpenIpcHandle,
    .ipc.close_ipc_handle = trackingCloseIpcHandle};

umf_result_t umfTrackingMemoryProviderCreate(
    umf_memory_provider_handle_t hUpstream, umf_memory_pool_handle_t hPool,
    umf_memory_provider_handle_t *hTrackingProvider) {

    umf_tracking_memory_provider_t params;
    params.hUpstream = hUpstream;
    params.hTracker = TRACKER;
    if (!params.hTracker) {
        return UMF_RESULT_ERROR_UNKNOWN;
    }
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

umf_memory_tracker_handle_t umfMemoryTrackerCreate(void) {
    umf_memory_tracker_handle_t handle =
        umf_ba_global_alloc(sizeof(struct umf_memory_tracker_t));
    if (!handle) {
        return NULL;
    }

    umf_ba_pool_t *tracker_allocator =
        umf_ba_create(sizeof(struct tracker_value_t));
    if (!tracker_allocator) {
        goto err_free_handle;
    }

    handle->tracker_allocator = tracker_allocator;

    void *mutex_ptr = util_mutex_init(&handle->splitMergeMutex);
    if (!mutex_ptr) {
        goto err_destroy_tracker_allocator;
    }

    handle->map = critnib_new();
    if (!handle->map) {
        goto err_destroy_mutex;
    }

    return handle;

err_destroy_mutex:
    util_mutex_destroy_not_free(&handle->splitMergeMutex);
err_destroy_tracker_allocator:
    umf_ba_destroy(tracker_allocator);
err_free_handle:
    umf_ba_global_free(handle);
    return NULL;
}

void umfMemoryTrackerDestroy(umf_memory_tracker_handle_t handle) {
    if (!handle) {
        return;
    }

    // Do not destroy if we are running in the proxy library,
    // because it may need those resources till
    // the very end of exiting the application.
    if (util_is_running_in_proxy_lib()) {
        return;
    }

#ifndef NDEBUG
    check_if_tracker_is_empty(handle, NULL);
#endif /* NDEBUG */

    // We have to zero all inner pointers,
    // because the tracker handle can be copied
    // and used in many places.
    critnib_delete(handle->map);
    handle->map = NULL;
    util_mutex_destroy_not_free(&handle->splitMergeMutex);
    umf_ba_destroy(handle->tracker_allocator);
    handle->tracker_allocator = NULL;
    umf_ba_global_free(handle);
}
