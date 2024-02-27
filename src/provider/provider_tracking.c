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
#include "utils_common.h"
#include "utils_concurrency.h"

#include <umf/memory_pool.h>
#include <umf/memory_provider.h>
#include <umf/memory_provider_ops.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct tracker_value_t {
    umf_memory_pool_handle_t pool;
    size_t size;
} tracker_value_t;

static umf_result_t umfMemoryTrackerAdd(umf_memory_tracker_handle_t hTracker,
                                        umf_memory_pool_handle_t pool,
                                        const void *ptr, size_t size) {
    assert(ptr);

    tracker_value_t *value =
        (tracker_value_t *)umf_ba_alloc(hTracker->tracker_allocator);
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

    void *value = critnib_remove(hTracker->map, (uintptr_t)ptr);
    if (!value) {
        // This should not happen
        // TODO: add logging here
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    umf_ba_free(hTracker->tracker_allocator, value);

    return UMF_RESULT_SUCCESS;
}

umf_memory_pool_handle_t umfMemoryTrackerGetPool(const void *ptr) {
    assert(ptr);

    if (TRACKER == NULL) {
        fprintf(stderr, "tracker is not created\n");
        return NULL;
    }

    if (TRACKER->map == NULL) {
        fprintf(stderr, "tracker's map is not created\n");
        return NULL;
    }

    uintptr_t rkey;
    tracker_value_t *rvalue;
    int found = critnib_find(TRACKER->map, (uintptr_t)ptr, FIND_LE,
                             (void *)&rkey, (void **)&rvalue);
    if (!found) {
        return NULL;
    }

    return (rkey + rvalue->size >= (uintptr_t)ptr) ? rvalue->pool : NULL;
}

typedef struct umf_tracking_memory_provider_t {
    umf_memory_provider_handle_t hUpstream;
    umf_memory_tracker_handle_t hTracker;
    umf_memory_pool_handle_t pool;
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

    umf_result_t ret2 = umfMemoryTrackerAdd(p->hTracker, p->pool, *ptr, size);
    if (ret2 != UMF_RESULT_SUCCESS) {
        // DO NOT call umfMemoryProviderFree() here, because the tracking provider
        // cannot change behaviour of the upstream provider.
        // TODO: LOG
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
        (tracker_value_t *)umf_ba_alloc(provider->hTracker->tracker_allocator);
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
        fprintf(stderr, "tracking split: no such value\n");
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err;
    }
    if (value->size != totalSize) {
        fprintf(stderr, "tracking split: %zu != %zu\n", value->size, totalSize);
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err;
    }

    ret = umfMemoryProviderAllocationSplit(provider->hUpstream, ptr, totalSize,
                                           firstSize);
    if (ret != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "tracking split: umfMemoryProviderAllocationSplit failed\n");
        goto err;
    }

    void *highPtr = (void *)(((uintptr_t)ptr) + firstSize);
    size_t secondSize = totalSize - firstSize;

    // We'll have a duplicate entry for the range [highPtr, highValue->size] but this is fine,
    // the value is the same anyway and we forbid removing that range concurrently
    ret = umfMemoryTrackerAdd(provider->hTracker, provider->pool, highPtr,
                              secondSize);
    if (ret != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "tracking split: umfMemoryTrackerAdd failed\n");
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
        (tracker_value_t *)umf_ba_alloc(provider->hTracker->tracker_allocator);

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
        fprintf(stderr, "tracking merge: no left value\n");
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err;
    }
    tracker_value_t *highValue = (tracker_value_t *)critnib_get(
        provider->hTracker->map, (uintptr_t)highPtr);
    if (!highValue) {
        fprintf(stderr, "tracking merge: no right value\n");
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err;
    }
    if (lowValue->pool != highValue->pool) {
        fprintf(stderr, "tracking merge: pool mismatch\n");
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err;
    }
    if (lowValue->size + highValue->size != totalSize) {
        fprintf(stderr, "tracking merge: lowValue->size + highValue->size != "
                        "totalSize\n");
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err;
    }

    ret = umfMemoryProviderAllocationMerge(provider->hUpstream, lowPtr, highPtr,
                                           totalSize);
    if (ret != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "tracking merge: umfMemoryProviderAllocationMerge failed\n");
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

    // umfMemoryTrackerRemove should be called before umfMemoryProviderFree
    // to avoid a race condition. If the order would be different, other thread
    // could allocate the memory at address `ptr` before a call to umfMemoryTrackerRemove
    // resulting in inconsistent state.
    if (ptr) {
        ret = umfMemoryTrackerRemove(p->hTracker, ptr, size);
        if (ret != UMF_RESULT_SUCCESS) {
            // DO NOT return an error here, because the tracking provider
            // cannot change behaviour of the upstream provider.
            // TODO: LOG
        }
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
        (umf_tracking_memory_provider_t *)umf_ba_global_alloc(
            sizeof(umf_tracking_memory_provider_t));
    if (!provider) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    *provider = *((umf_tracking_memory_provider_t *)params);
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
        if (pool) {
            fprintf(stderr,
                    "ASSERT: tracking provider of pool %p is not empty! "
                    "(%zu items left)\n",
                    (void *)pool, n_items);
        } else {
            fprintf(stderr,
                    "ASSERT: tracking provider is not empty! (%zu items "
                    "left)\n",
                    n_items);
        }
        assert(n_items == 0);
    }
}
#endif /* NDEBUG */

static void trackingFinalize(void *provider) {
#ifndef NDEBUG
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
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
    .allocation_split = trackingAllocationSplit,
    .allocation_merge = trackingAllocationMerge};

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
        (umf_memory_tracker_handle_t)umf_ba_global_alloc(
            sizeof(struct umf_memory_tracker_t));
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
