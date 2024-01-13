/*
 *
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "provider_tracking.h"
#include "critnib.h"

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

static umf_result_t trackingAllocationSplit(void *provider, void *ptr,
                                            size_t totalSize, size_t leftSize) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;

    tracker_value_t *splitValue =
        (tracker_value_t *)malloc(sizeof(tracker_value_t));
    splitValue->pool = p->pool;
    splitValue->size = leftSize;

    tracker_value_t *value =
        (tracker_value_t *)critnib_get((critnib *)p->hTracker, (uintptr_t)ptr);
    if (!value) {
        free(splitValue);
        fprintf(stderr, "tracking split: no such value\n");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    if (value->size != totalSize) {
        free(splitValue);
        fprintf(stderr, "tracking split: %zu != %zu\n", value->size, totalSize);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_result_t ret = umfMemoryProviderAllocationSplit(p->hUpstream, ptr,
                                                        totalSize, leftSize);
    if (ret != UMF_RESULT_SUCCESS) {
        free(splitValue);
        fprintf(stderr,
                "tracking split: umfMemoryProviderAllocationSplit failed\n");
        return ret;
    }

    void *rightPtr = (void *)(((uintptr_t)ptr) + leftSize);
    size_t rightSize = totalSize - leftSize;

    // We'll have duplicate entry for the range [rightPtr, rightValue->size] but this is fine,
    // the value is the same anyway and we forbid splitting/removing that range concurrently
    ret = umfMemoryTrackerAdd(p->hTracker, p->pool, rightPtr, rightSize);
    if (ret != UMF_RESULT_SUCCESS) {
        free(splitValue);
        fprintf(stderr, "tracking split: umfMemoryTrackerAdd failed\n");
        // TODO: what now? should we rollback the split? This is can only happen due to ENOMEM
        // so it's unlikely but probably the best solution would be to try to preallocate everything
        // (value and critnib nodes) before calling umfMemoryProviderAllocationSplit.
        return ret;
    }

    int cret = critnib_insert((critnib *)p->hTracker, (uintptr_t)ptr,
                              (void *)splitValue, 1 /* update */);
    // this cannot fail since we know the element exists (nothing to allocate)
    assert(cret == 0);
    (void)cret;

    // free the original value
    free(value);

    return UMF_RESULT_SUCCESS;
}

static umf_result_t trackingAllocationMerge(void *provider, void *leftPtr,
                                            void *rightPtr, size_t totalSize) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;

    tracker_value_t *mergedValue =
        (tracker_value_t *)malloc(sizeof(tracker_value_t));
    mergedValue->pool = p->pool;
    mergedValue->size = totalSize;

    if (!mergedValue) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    tracker_value_t *leftValue = (tracker_value_t *)critnib_get(
        (critnib *)p->hTracker, (uintptr_t)leftPtr);
    if (!leftValue) {
        free(mergedValue);
        fprintf(stderr, "tracking merge: no left value\n");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    tracker_value_t *rightValue = (tracker_value_t *)critnib_get(
        (critnib *)p->hTracker, (uintptr_t)rightPtr);
    if (!rightValue) {
        free(mergedValue);
        fprintf(stderr, "tracking merge: no right value\n");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    if (leftValue->pool != rightValue->pool) {
        free(mergedValue);
        fprintf(stderr, "tracking merge: pool mismatch\n");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    if (leftValue->size + rightValue->size != totalSize) {
        // TODO: should we allow leftValue->size + rightValue->size > totalSize?
        fprintf(stderr, "tracking merge: leftValue->size + rightValue->size != "
                        "totalSize\n");
        free(mergedValue);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_result_t ret = umfMemoryProviderAllocationMerge(p->hUpstream, leftPtr,
                                                        rightPtr, totalSize);
    if (ret != UMF_RESULT_SUCCESS) {
        free(mergedValue);
        fprintf(stderr,
                "tracking merge: umfMemoryProviderAllocationMerge failed\n");
        return ret;
    }

    // We'll have duplicate entry for the range [rightPtr, rightValue->size] but this is fine,
    // the value is the same anyway and we forbid splitting/removing that range concurrently
    int cret = critnib_insert((critnib *)p->hTracker, (uintptr_t)leftPtr,
                              (void *)mergedValue, 1 /* update */);
    // this cannot fail since we know the element exists (nothing to allocate)
    assert(cret == 0);
    (void)cret;

    // free old value that we just replaced with mergedValue
    free(leftValue);

    void *erasedRightValue =
        critnib_remove((critnib *)p->hTracker, (uintptr_t)rightPtr);
    assert(erasedRightValue == rightValue);
    free(erasedRightValue);

    return UMF_RESULT_SUCCESS;
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
#ifndef NDEBUG
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;

    uintptr_t rkey;
    void *rvalue;
    size_t n_items = 0;
    uintptr_t last_key = 0;

    while (1 == critnib_find((critnib *)p->hTracker, last_key, FIND_G, &rkey,
                             &rvalue)) {
        tracker_value_t *value = (tracker_value_t *)rvalue;
        if (value->pool == p->pool) {
            n_items++;
        }

        last_key = rkey;
    }

    if (n_items) {
        fprintf(stderr,
                "ASSERT: tracking provider of pool %p is not empty! (%zu items "
                "left)\n",
                (void *)p->pool, n_items);
        assert(n_items == 0);
    }
#endif /* NDEBUG */

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
    umfTrackingMemoryProviderInit();

    umf_tracking_memory_provider_t params;
    params.hUpstream = hUpstream;
    params.hTracker = umfMemoryTrackerGet();
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

void umfTrackingMemoryProviderFini(void *tracker) {
#ifndef NDEBUG
    uintptr_t rkey;
    void *rvalue;
    size_t n_items = 0;
    uintptr_t last_key = 0;

    while (1 ==
           critnib_find((critnib *)tracker, last_key, FIND_G, &rkey, &rvalue)) {
        n_items++;
        last_key = rkey;
    }

    if (n_items) {
        fprintf(stderr,
                "ASSERT: tracking provider is not empty! (%zu items left)\n",
                n_items);
        assert(n_items == 0);
    }
#endif /* NDEBUG */

    critnib_delete((critnib *)tracker);
}
