/*
 *
 * Copyright (C) 2023-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <umf/memory_pool.h>
#include <umf/memory_provider.h>
#include <umf/memory_provider_ops.h>

#include "base_alloc_global.h"
#include "critnib.h"
#include "ipc_cache.h"
#include "ipc_internal.h"
#include "provider_tracking.h"
#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_log.h"

// TODO: we need to support an arbitrary amount of layers in the future
#define MAX_LEVELS_OF_ALLOC_SEGMENT_MAP 8

uint64_t IPC_HANDLE_ID = 0;

struct umf_memory_tracker_t {
    umf_ba_pool_t *alloc_info_allocator;
    // Multilevel maps are needed to support the case
    // when one memory pool acts as a memory provider
    // for another memory pool (nested memory pooling).
    critnib *alloc_segments_map[MAX_LEVELS_OF_ALLOC_SEGMENT_MAP];
    utils_mutex_t mutex;
};

typedef struct tracker_alloc_info_t {
    umf_memory_pool_handle_t pool;
    size_t size;
    // number of overlapping memory regions
    // in the next level of map
    // falling within the current range
    size_t n_children;
} tracker_alloc_info_t;

// Get the most nested (on the highest level) allocation segment in the map with the `ptr` key.
// If `no_children` is set to 1, the function will return the entry
// only if it has no children on the higher level.
// The function returns the entry if found, otherwise NULL.
static tracker_alloc_info_t *get_most_nested_alloc_segment(
    umf_memory_tracker_handle_t hTracker, const void *ptr, int *_level,
    uintptr_t *_parent_key, tracker_alloc_info_t **_parent_value,
    int no_children) {
    assert(ptr);

    tracker_alloc_info_t *parent_value = NULL;
    tracker_alloc_info_t *rvalue = NULL;
    uintptr_t parent_key = 0;
    uintptr_t rkey = 0;
    uint64_t rsize = 0;
    int level = 0;
    int found = 0;

    do {
        assert(level < MAX_LEVELS_OF_ALLOC_SEGMENT_MAP);
        found =
            critnib_find(hTracker->alloc_segments_map[level], (uintptr_t)ptr,
                         FIND_LE, (void *)&rkey, (void **)&rvalue);
        if (!found || !rvalue) {
            break;
        }

        utils_atomic_load_acquire_u64((uint64_t *)&rvalue->size, &rsize);

        if (found && (uintptr_t)ptr < rkey + rsize) {
            if (rvalue->n_children) {
                if (level == MAX_LEVELS_OF_ALLOC_SEGMENT_MAP - 1) {
                    break;
                }
                level++;
                parent_key = rkey;
                parent_value = rvalue;
            }
        }
    } while (found && ((uintptr_t)ptr < rkey + rsize) && rvalue->n_children);

    if (!rvalue || rkey != (uintptr_t)ptr) {
        return NULL;
    }

    if (no_children && (rvalue->n_children > 0)) {
        return NULL;
    }

    if (_level) {
        *_level = level;
    }
    if (_parent_key) {
        *_parent_key = parent_key;
    }
    if (_parent_value) {
        *_parent_value = parent_value;
    }

    assert(!no_children || rvalue->n_children == 0);

    return rvalue;
}

static umf_result_t
umfMemoryTrackerAddAtLevel(umf_memory_tracker_handle_t hTracker, int level,
                           umf_memory_pool_handle_t pool, const void *ptr,
                           size_t size, uintptr_t parent_key,
                           tracker_alloc_info_t *parent_value) {
    assert(ptr);

    umf_result_t umf_result = UMF_RESULT_ERROR_UNKNOWN;

    tracker_alloc_info_t *value = umf_ba_alloc(hTracker->alloc_info_allocator);
    if (value == NULL) {
        LOG_ERR("failed to allocate a tracker value, ptr=%p, size=%zu", ptr,
                size);
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    value->pool = pool;
    utils_atomic_store_release_u64(&value->size, size);
    value->n_children = 0;

    assert(level < MAX_LEVELS_OF_ALLOC_SEGMENT_MAP);
    int ret = critnib_insert(hTracker->alloc_segments_map[level],
                             (uintptr_t)ptr, value, 0);
    if (ret == 0) {
        LOG_DEBUG("memory region is added, tracker=%p, level=%i, pool=%p, "
                  "ptr=%p, size=%zu",
                  (void *)hTracker, level, (void *)pool, ptr, size);

        if (parent_value) {
            parent_value->n_children++;
            LOG_DEBUG(
                "child #%zu added to memory region: tracker=%p, level=%i, "
                "pool=%p, ptr=%p, size=%zu",
                parent_value->n_children, (void *)hTracker, level - 1,
                (void *)parent_value->pool, (void *)parent_key,
                parent_value->size);
        }
        return UMF_RESULT_SUCCESS;
    }
    if (ret == ENOMEM) {
        umf_result = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    LOG_ERR(
        "failed to insert the tracker value: pool=%p, ptr=%p, size=%zu, ret=%d",
        (void *)pool, ptr, size, ret);

    umf_ba_free(hTracker->alloc_info_allocator, value);

    return umf_result;
}

static umf_result_t umfMemoryTrackerAdd(umf_memory_tracker_handle_t hTracker,
                                        umf_memory_pool_handle_t pool,
                                        const void *ptr, size_t size) {
    assert(ptr);

    umf_result_t umf_result = UMF_RESULT_ERROR_UNKNOWN;
    tracker_alloc_info_t *parent_value = NULL;
    tracker_alloc_info_t *rvalue = NULL;
    uintptr_t parent_key = 0;
    uintptr_t rkey = 0;
    uint64_t rsize = 0;
    int level = 0;
    int found = 0;

    int ret = utils_mutex_lock(&hTracker->mutex);
    if (ret) {
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    // Find the most nested (in the highest level) entry
    // in the critnib maps that contains the given 'ptr' pointer.
    do {
        assert(level < MAX_LEVELS_OF_ALLOC_SEGMENT_MAP);
        found =
            critnib_find(hTracker->alloc_segments_map[level], (uintptr_t)ptr,
                         FIND_LE, (void *)&rkey, (void **)&rvalue);
        if (!found || !rvalue) {
            break;
        }

        utils_atomic_load_acquire_u64((uint64_t *)&rvalue->size, &rsize);

        if ((uintptr_t)ptr < rkey + rsize) {
            if (level == MAX_LEVELS_OF_ALLOC_SEGMENT_MAP - 1) {
                // TODO: we need to support an arbitrary amount of layers in the future
                LOG_ERR("tracker level is too high, ptr=%p, size=%zu", ptr,
                        size);
                umf_result = UMF_RESULT_ERROR_OUT_OF_RESOURCES;
                goto err_unlock;
            }
            if (((uintptr_t)ptr + size) > (rkey + rsize)) {
                LOG_ERR(
                    "cannot insert to the tracker value (pool=%p, ptr=%p, "
                    "size=%zu) "
                    "that exceeds the parent value (pool=%p, ptr=%p, size=%zu)",
                    (void *)pool, ptr, size, (void *)rvalue->pool, (void *)rkey,
                    (size_t)rsize);
                umf_result = UMF_RESULT_ERROR_INVALID_ARGUMENT;
                goto err_unlock;
            }
            parent_key = rkey;
            parent_value = rvalue;
            level++;
        }
    } while (found && ((uintptr_t)ptr < rkey + rsize) && rvalue->n_children);

    umf_result = umfMemoryTrackerAddAtLevel(hTracker, level, pool, ptr, size,
                                            parent_key, parent_value);
    if (umf_result != UMF_RESULT_SUCCESS) {
        goto err_unlock;
    }

    umf_result = UMF_RESULT_SUCCESS;

err_unlock:
    utils_mutex_unlock(&hTracker->mutex);

    return umf_result;
}

static umf_result_t umfMemoryTrackerRemove(umf_memory_tracker_handle_t hTracker,
                                           const void *ptr) {
    assert(ptr);

    // TODO: there is no support for removing partial ranges (or multiple entries
    // in a single remove call) yet.
    // Every umfMemoryTrackerAdd(..., ptr, ...) should have a corresponding
    // umfMemoryTrackerRemove call with the same ptr value.

    umf_result_t umf_result = UMF_RESULT_ERROR_UNKNOWN;
    tracker_alloc_info_t *parent_value = NULL;
    uintptr_t parent_key = 0;
    int level = 0;

    int ret = utils_mutex_lock(&hTracker->mutex);
    if (ret) {
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    // Find the most nested (on the highest level) entry in the map
    // with the `ptr` key and with no children - only such entry can be removed.
    tracker_alloc_info_t *value = get_most_nested_alloc_segment(
        hTracker, ptr, &level, &parent_key, &parent_value, 1 /* no_children */);
    if (!value) {
        LOG_ERR("pointer %p not found in the alloc_segments_map", ptr);
        goto err_unlock;
    }

    assert(level < MAX_LEVELS_OF_ALLOC_SEGMENT_MAP);
    value = critnib_remove(hTracker->alloc_segments_map[level], (uintptr_t)ptr);
    assert(value);

    LOG_DEBUG("memory region removed: tracker=%p, level=%i, pool=%p, ptr=%p, "
              "size=%zu",
              (void *)hTracker, level, value->pool, ptr, value->size);

    if (parent_value) {
        LOG_DEBUG(
            "child #%zu removed from memory region: tracker=%p, level=%i, "
            "pool=%p, ptr=%p, size=%zu",
            parent_value->n_children, (void *)hTracker, level - 1,
            (void *)parent_value->pool, (void *)parent_key, parent_value->size);
        parent_value->n_children--;
    }

    umf_ba_free(hTracker->alloc_info_allocator, value);

    umf_result = UMF_RESULT_SUCCESS;

err_unlock:
    utils_mutex_unlock(&hTracker->mutex);

    return umf_result;
}

umf_memory_pool_handle_t umfMemoryTrackerGetPool(const void *ptr) {
    umf_alloc_info_t allocInfo = {NULL, 0, NULL};
    umf_result_t ret = umfMemoryTrackerGetAllocInfo(ptr, &allocInfo);
    if (ret != UMF_RESULT_SUCCESS) {
        return NULL;
    }

    return allocInfo.pool;
}

umf_result_t umfMemoryTrackerGetAllocInfo(const void *ptr,
                                          umf_alloc_info_t *pAllocInfo) {
    assert(pAllocInfo);

    if (ptr == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (TRACKER == NULL) {
        LOG_ERR("tracker does not exist");
        return UMF_RESULT_ERROR_NOT_SUPPORTED;
    }

    if (TRACKER->alloc_segments_map[0] == NULL) {
        LOG_ERR("tracker's alloc_segments_map does not exist");
        return UMF_RESULT_ERROR_NOT_SUPPORTED;
    }

    tracker_alloc_info_t *top_most_value = NULL;
    tracker_alloc_info_t *rvalue = NULL;
    uintptr_t top_most_key = 0;
    uintptr_t rkey = 0;
    int level = 0;
    int found = 0;

    do {
        assert(level < MAX_LEVELS_OF_ALLOC_SEGMENT_MAP);
        found = critnib_find(TRACKER->alloc_segments_map[level], (uintptr_t)ptr,
                             FIND_LE, (void *)&rkey, (void **)&rvalue);
        if (found && (uintptr_t)ptr < rkey + rvalue->size) {
            top_most_key = rkey;
            top_most_value = rvalue;
            if (rvalue->n_children == 0 ||
                level == MAX_LEVELS_OF_ALLOC_SEGMENT_MAP - 1) {
                break;
            }
            level++;
        }
    } while (found && (uintptr_t)ptr < rkey + rvalue->size &&
             rvalue->n_children);

    if (!top_most_value) {
        LOG_DEBUG("pointer %p not found in the tracker, TRACKER=%p", ptr,
                  (void *)TRACKER);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    pAllocInfo->base = (void *)top_most_key;
    pAllocInfo->baseSize = top_most_value->size;
    pAllocInfo->pool = top_most_value->pool;

    return UMF_RESULT_SUCCESS;
}

// Cache entry structure to store provider-specific IPC data.
// providerIpcData is a Flexible Array Member because its size varies
// depending on the provider.
typedef struct ipc_cache_value_t {
    uint64_t handle_id;
    uint64_t ipcDataSize;
    char providerIpcData[];
} ipc_cache_value_t;

typedef struct umf_tracking_memory_provider_t {
    umf_memory_provider_handle_t hUpstream;
    umf_memory_tracker_handle_t hTracker;
    umf_memory_pool_handle_t pool;
    critnib *ipcCache;
    ipc_opened_cache_handle_t hIpcMappedCache;
} umf_tracking_memory_provider_t;

typedef struct umf_tracking_memory_provider_t umf_tracking_memory_provider_t;

static umf_result_t trackingAlloc(void *hProvider, size_t size,
                                  size_t alignment, void **_ptr) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)hProvider;
    umf_result_t ret = UMF_RESULT_SUCCESS;
    void *ptr;

    assert(p->hUpstream);

    *_ptr = NULL;

    ret = umfMemoryProviderAlloc(p->hUpstream, size, alignment, &ptr);
    if (ret != UMF_RESULT_SUCCESS || !ptr) {
        return ret;
    }

    ret = umfMemoryTrackerAdd(p->hTracker, p->pool, ptr, size);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("failed to add allocated region to the tracker, ptr = %p, size "
                "= %zu, ret = %d",
                ptr, size, ret);
        umf_result_t ret2 = umfMemoryProviderFree(p->hUpstream, ptr, size);
        if (ret2 != UMF_RESULT_SUCCESS) {
            LOG_ERR("upstream provider failed to free the memory: ptr = %p, "
                    "size = %zu, ret = %d",
                    ptr, size, ret2);
        }
        return ret;
    }

    *_ptr = ptr;

    return UMF_RESULT_SUCCESS;
}

static umf_result_t trackingAllocationSplit(void *hProvider, void *ptr,
                                            size_t totalSize,
                                            size_t firstSize) {
    umf_result_t ret = UMF_RESULT_ERROR_UNKNOWN;
    umf_tracking_memory_provider_t *provider =
        (umf_tracking_memory_provider_t *)hProvider;
    tracker_alloc_info_t *parent_value = NULL;
    uintptr_t parent_key = 0;

    tracker_alloc_info_t *splitValue =
        umf_ba_alloc(provider->hTracker->alloc_info_allocator);
    if (!splitValue) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    splitValue->pool = provider->pool;
    splitValue->size = firstSize;
    splitValue->n_children = 0;

    int r = utils_mutex_lock(&provider->hTracker->mutex);
    if (r) {
        goto err_lock;
    }

    int level = 0;

    // Find the most nested (on the highest level) entry in the map
    // with the `ptr` key and with no children - only such entry can be split.
    tracker_alloc_info_t *value = get_most_nested_alloc_segment(
        provider->hTracker, ptr, &level, &parent_key, &parent_value,
        1 /* no_children */);
    if (!value) {
        LOG_ERR("region for split is not found in the tracker");
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err;
    }
    if (value->size != totalSize) {
        LOG_ERR("tracked size=%zu does not match requested size to split: %zu",
                value->size, totalSize);
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err;
    }

    ret = umfMemoryProviderAllocationSplit(provider->hUpstream, ptr, totalSize,
                                           firstSize);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("upstream provider failed to split the region");
        goto err;
    }

    assert(level < MAX_LEVELS_OF_ALLOC_SEGMENT_MAP);
    int cret =
        critnib_insert(provider->hTracker->alloc_segments_map[level],
                       (uintptr_t)ptr, (void *)splitValue, 1 /* update */);
    // this cannot fail since we know the element exists (nothing to allocate)
    assert(cret == 0);
    (void)cret;

    void *highPtr = (void *)(((uintptr_t)ptr) + firstSize);
    size_t secondSize = totalSize - firstSize;

    // We'll have a duplicate entry for the range [highPtr, highValue->size] but this is fine,
    // the value is the same anyway and we forbid removing that range concurrently
    ret = umfMemoryTrackerAddAtLevel(provider->hTracker, level, provider->pool,
                                     highPtr, secondSize, parent_key,
                                     parent_value);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("failed to add the split region to the tracker, ptr=%p, "
                "size=%zu, ret=%d",
                highPtr, secondSize, ret);
        // revert the split
        assert(level < MAX_LEVELS_OF_ALLOC_SEGMENT_MAP);
        cret = critnib_insert(provider->hTracker->alloc_segments_map[level],
                              (uintptr_t)ptr, (void *)value, 1 /* update */);
        // this cannot fail since we know the element exists (nothing to allocate)
        assert(cret == 0);
        (void)cret;
        // TODO: what now? should we rollback the split? This can only happen due to ENOMEM
        // so it's unlikely but probably the best solution would be to try to preallocate everything
        // (value and critnib nodes) before calling umfMemoryProviderAllocationSplit.
        goto err;
    }

    // free the original value
    umf_ba_free(provider->hTracker->alloc_info_allocator, value);
    utils_mutex_unlock(&provider->hTracker->mutex);

    LOG_DEBUG(
        "split memory region (level=%i): ptr=%p, totalSize=%zu, firstSize=%zu",
        level, ptr, totalSize, firstSize);

    return UMF_RESULT_SUCCESS;

err:
    utils_mutex_unlock(&provider->hTracker->mutex);
err_lock:
    umf_ba_free(provider->hTracker->alloc_info_allocator, splitValue);

    LOG_ERR(
        "failed to split memory region: ptr=%p, totalSize=%zu, firstSize=%zu",
        ptr, totalSize, firstSize);

    return ret;
}

static umf_result_t trackingAllocationMerge(void *hProvider, void *lowPtr,
                                            void *highPtr, size_t totalSize) {
    umf_result_t ret = UMF_RESULT_ERROR_UNKNOWN;
    umf_tracking_memory_provider_t *provider =
        (umf_tracking_memory_provider_t *)hProvider;

    tracker_alloc_info_t *mergedValue =
        umf_ba_alloc(provider->hTracker->alloc_info_allocator);

    if (!mergedValue) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    mergedValue->pool = provider->pool;
    mergedValue->size = totalSize;
    mergedValue->n_children = 0;

    // any different negative values
    int lowLevel = -2;
    int highLevel = -1;

    int r = utils_mutex_lock(&provider->hTracker->mutex);
    if (r) {
        goto err_lock;
    }

    tracker_alloc_info_t *lowValue = get_most_nested_alloc_segment(
        provider->hTracker, lowPtr, &lowLevel, NULL, NULL,
        0 /* no_children */); // can have children
    if (!lowValue) {
        LOG_FATAL("no left value");
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err_assert;
    }
    tracker_alloc_info_t *highValue = get_most_nested_alloc_segment(
        provider->hTracker, highPtr, &highLevel, NULL, NULL,
        0 /* no_children */); // can have children
    if (!highValue) {
        LOG_FATAL("no right value");
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err_assert;
    }
    if (lowLevel != highLevel) {
        LOG_FATAL("tracker level mismatch");
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err_assert;
    }
    if (lowValue->pool != highValue->pool) {
        LOG_FATAL("pool mismatch");
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err_assert;
    }
    if (lowValue->size + highValue->size != totalSize) {
        LOG_FATAL("lowValue->size + highValue->size != totalSize");
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto err_assert;
    }

    mergedValue->n_children = lowValue->n_children + highValue->n_children;

    ret = umfMemoryProviderAllocationMerge(provider->hUpstream, lowPtr, highPtr,
                                           totalSize);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_WARN("upstream provider failed to merge regions");
        goto not_merged;
    }

    size_t lno = lowValue->n_children;
    size_t hno = highValue->n_children;

    // We'll have a duplicate entry for the range [highPtr, highValue->size] but this is fine,
    // the value is the same anyway and we forbid removing that range concurrently
    int cret =
        critnib_insert(provider->hTracker->alloc_segments_map[lowLevel],
                       (uintptr_t)lowPtr, (void *)mergedValue, 1 /* update */);
    // this cannot fail since we know the element exists (nothing to allocate)
    assert(cret == 0);
    (void)cret;

    // free old value that we just replaced with mergedValue
    umf_ba_free(provider->hTracker->alloc_info_allocator, lowValue);

    void *erasedhighValue = critnib_remove(
        provider->hTracker->alloc_segments_map[highLevel], (uintptr_t)highPtr);
    assert(erasedhighValue == highValue);

    umf_ba_free(provider->hTracker->alloc_info_allocator, erasedhighValue);

    utils_mutex_unlock(&provider->hTracker->mutex);

    LOG_DEBUG("merged memory regions (level=%i): lowPtr=%p (child=%zu), "
              "highPtr=%p (child=%zu), totalSize=%zu",
              lowLevel, lowPtr, lno, highPtr, hno, totalSize);

    return UMF_RESULT_SUCCESS;

err_assert:
    LOG_FATAL("failed to merge memory regions: lowPtr=%p (level=%i), "
              "highPtr=%p (level=%i), totalSize=%zu",
              lowPtr, lowLevel, highPtr, highLevel, totalSize);
    assert(0);

not_merged:
    utils_mutex_unlock(&provider->hTracker->mutex);

err_lock:
    umf_ba_free(provider->hTracker->alloc_info_allocator, mergedValue);

    LOG_ERR("failed to merge memory regions: lowPtr=%p (level=%i), highPtr=%p "
            "(level=%i), totalSize=%zu",
            lowPtr, lowLevel, highPtr, highLevel, totalSize);

    return ret;
}

static umf_result_t trackingFree(void *hProvider, void *ptr, size_t size) {
    umf_result_t ret;
    umf_result_t ret_remove = UMF_RESULT_ERROR_UNKNOWN;
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)hProvider;

    // umfMemoryTrackerRemove should be called before umfMemoryProviderFree
    // to avoid a race condition. If the order would be different, other thread
    // could allocate the memory at address `ptr` before a call to umfMemoryTrackerRemove
    // resulting in inconsistent state.
    if (ptr) {
        ret_remove = umfMemoryTrackerRemove(p->hTracker, ptr);
        if (ret_remove != UMF_RESULT_SUCCESS) {
            // DO NOT return an error here, because the tracking provider
            // cannot change behaviour of the upstream provider.
            LOG_ERR("failed to remove the region from the tracker, ptr=%p, "
                    "size=%zu, ret = %d",
                    ptr, size, ret_remove);
        }
    }

    void *value = critnib_remove(p->ipcCache, (uintptr_t)ptr);
    if (value) {
        ipc_cache_value_t *cache_value = (ipc_cache_value_t *)value;
        ret = umfMemoryProviderPutIPCHandle(p->hUpstream,
                                            cache_value->providerIpcData);
        if (ret != UMF_RESULT_SUCCESS) {
            LOG_ERR("upstream provider failed to put IPC handle, ptr=%p, "
                    "size=%zu, ret = %d",
                    ptr, size, ret);
        }
        umf_ba_global_free(value);
    }

    ret = umfMemoryProviderFree(p->hUpstream, ptr, size);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("upstream provider failed to free the memory");
        // Do not add memory back to the tracker,
        // if it had not been removed.
        if (ret_remove != UMF_RESULT_SUCCESS) {
            return ret;
        }

        if (umfMemoryTrackerAdd(p->hTracker, p->pool, ptr, size) !=
            UMF_RESULT_SUCCESS) {
            LOG_ERR(
                "cannot add memory back to the tracker, ptr = %p, size = %zu",
                ptr, size);
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
    size_t n_items = 0;

    for (int i = 0; i < MAX_LEVELS_OF_ALLOC_SEGMENT_MAP; i++) {
        uintptr_t last_key = 0;
        uintptr_t rkey;
        tracker_alloc_info_t *rvalue;

        while (1 == critnib_find(hTracker->alloc_segments_map[i], last_key,
                                 FIND_G, &rkey, (void **)&rvalue)) {
            if (rvalue->pool == pool || pool == NULL) {
                n_items++;
            }

            last_key = rkey;
        }
    }

    if (n_items) {
        // Do not log the error if we are running in the proxy library,
        // because it may need those resources till
        // the very end of exiting the application.
        if (!utils_is_running_in_proxy_lib()) {
            if (pool) {
                LOG_ERR("tracking provider of pool %p is not empty! (%zu items "
                        "left)",
                        (void *)pool, n_items);
            } else {
                LOG_ERR("tracking provider is not empty! (%zu items left)",
                        n_items);
            }

#ifdef UMF_DEVELOPER_MODE
            assert(n_items == 0 && "tracking provider is not empty!");
#endif
        }
    }
}
#endif /* NDEBUG */

static void trackingFinalize(void *provider) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;

    umfIpcOpenedCacheDestroy(p->hIpcMappedCache);

    critnib_delete(p->ipcCache);

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

static inline umf_ipc_data_t *getIpcDataFromIpcHandle(void *providerIpcData) {
    return (umf_ipc_data_t *)((uint8_t *)providerIpcData -
                              sizeof(umf_ipc_data_t));
}

static umf_result_t trackingGetIpcHandle(void *provider, const void *ptr,
                                         size_t size, void *providerIpcData) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    umf_result_t ret = UMF_RESULT_SUCCESS;
    size_t ipcDataSize = 0;
    int cached = 0;
    ipc_cache_value_t *cache_value = NULL;
    umf_ipc_data_t *ipcUmfData = getIpcDataFromIpcHandle(providerIpcData);

    do {
        void *value = critnib_get(p->ipcCache, (uintptr_t)ptr);
        if (value) { //cache hit
            cache_value = (ipc_cache_value_t *)value;
            cached = 1;
        } else { //cache miss
            ret = umfMemoryProviderGetIPCHandleSize(p->hUpstream, &ipcDataSize);
            if (ret != UMF_RESULT_SUCCESS) {
                LOG_ERR("upstream provider failed to get the size of IPC "
                        "handle");
                return ret;
            }

            size_t value_size = sizeof(ipc_cache_value_t) + ipcDataSize;
            cache_value = umf_ba_global_alloc(value_size);
            if (!cache_value) {
                LOG_ERR("failed to allocate cache_value");
                return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
            }

            ret = umfMemoryProviderGetIPCHandle(p->hUpstream, ptr, size,
                                                cache_value->providerIpcData);
            if (ret != UMF_RESULT_SUCCESS) {
                LOG_ERR("upstream provider failed to get IPC handle");
                umf_ba_global_free(cache_value);
                return ret;
            }

            cache_value->handle_id = utils_atomic_increment_u64(&IPC_HANDLE_ID);
            cache_value->ipcDataSize = ipcDataSize;

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
                ret = umfMemoryProviderPutIPCHandle(
                    p->hUpstream, cache_value->providerIpcData);
                umf_ba_global_free(cache_value);
                if (ret != UMF_RESULT_SUCCESS) {
                    LOG_ERR("upstream provider failed to put IPC handle");
                    return ret;
                }
                if (insRes == ENOMEM) {
                    LOG_ERR("insert to IPC cache failed due to OOM");
                    return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
                }
            }
        }
    } while (!cached);

    memcpy(providerIpcData, cache_value->providerIpcData,
           cache_value->ipcDataSize);
    ipcUmfData->handle_id = cache_value->handle_id;

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

static void
ipcOpenedCacheEvictionCallback(const ipc_opened_cache_key_t *key,
                               const ipc_opened_cache_value_t *value) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)key->local_provider;
    // umfMemoryTrackerRemove should be called before umfMemoryProviderCloseIPCHandle
    // to avoid a race condition. If the order would be different, other thread
    // could allocate the memory at address `ptr` before a call to umfMemoryTrackerRemove
    // resulting in inconsistent state.
    if (value->mapped_base_ptr) {
        umf_result_t ret =
            umfMemoryTrackerRemove(p->hTracker, value->mapped_base_ptr);
        if (ret != UMF_RESULT_SUCCESS) {
            // DO NOT return an error here, because the tracking provider
            // cannot change behaviour of the upstream provider.
            LOG_ERR("failed to remove the region from the tracker, ptr=%p, "
                    "size=%zu, ret = %d",
                    value->mapped_base_ptr, value->mapped_size, ret);
        }
    }
    umf_result_t ret = umfMemoryProviderCloseIPCHandle(
        p->hUpstream, value->mapped_base_ptr, value->mapped_size);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("provider failed to close IPC handle, ptr=%p, size=%zu",
                value->mapped_base_ptr, value->mapped_size);
    }
}

static umf_result_t upstreamOpenIPCHandle(umf_tracking_memory_provider_t *p,
                                          void *providerIpcData,
                                          size_t bufferSize, void **ptr) {
    void *mapped_ptr = NULL;
    assert(p != NULL);
    assert(ptr != NULL);
    umf_result_t ret = umfMemoryProviderOpenIPCHandle(
        p->hUpstream, providerIpcData, &mapped_ptr);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("upstream provider failed to open IPC handle");
        return ret;
    }
    assert(mapped_ptr != NULL);

    ret = umfMemoryTrackerAdd(p->hTracker, p->pool, mapped_ptr, bufferSize);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("failed to add IPC region to the tracker, ptr=%p, "
                "size=%zu, "
                "ret = %d",
                mapped_ptr, bufferSize, ret);
        if (umfMemoryProviderCloseIPCHandle(p->hUpstream, mapped_ptr,
                                            bufferSize)) {
            LOG_ERR("upstream provider failed to close IPC handle, "
                    "ptr=%p, size=%zu",
                    mapped_ptr, bufferSize);
        }
        return ret;
    }

    *ptr = mapped_ptr;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t trackingOpenIpcHandle(void *provider, void *providerIpcData,
                                          void **ptr) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    umf_result_t ret = UMF_RESULT_SUCCESS;

    assert(p->hUpstream);
    assert(p->hIpcMappedCache);

    umf_ipc_data_t *ipcUmfData = getIpcDataFromIpcHandle(providerIpcData);

    // Compiler may add paddings to the ipc_opened_cache_key_t structure
    // so we need to zero it out to avoid false cache miss.
    ipc_opened_cache_key_t key = {0};
    key.remote_base_ptr = ipcUmfData->base;
    key.local_provider = provider;
    key.remote_pid = ipcUmfData->pid;

    ipc_opened_cache_value_t *cache_entry = NULL;
    ret = umfIpcOpenedCacheGet(p->hIpcMappedCache, &key, ipcUmfData->handle_id,
                               &cache_entry);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR("failed to get cache entry");
        return ret;
    }

    assert(cache_entry != NULL);

    void *mapped_ptr = NULL;
    utils_atomic_load_acquire_ptr(&(cache_entry->mapped_base_ptr),
                                  (void **)&mapped_ptr);
    if (mapped_ptr == NULL) {
        utils_mutex_lock(&(cache_entry->mmap_lock));
        utils_atomic_load_acquire_ptr(&(cache_entry->mapped_base_ptr),
                                      (void **)&mapped_ptr);
        if (mapped_ptr == NULL) {
            ret = upstreamOpenIPCHandle(p, providerIpcData,
                                        ipcUmfData->baseSize, &mapped_ptr);
            if (ret == UMF_RESULT_SUCCESS) {
                // Put to the cache
                cache_entry->mapped_size = ipcUmfData->baseSize;
                utils_atomic_store_release_ptr(&(cache_entry->mapped_base_ptr),
                                               mapped_ptr);
            }
        }
        utils_mutex_unlock(&(cache_entry->mmap_lock));
    }

    if (ret == UMF_RESULT_SUCCESS) {
        *ptr = mapped_ptr;
    }

    return ret;
}

static umf_result_t trackingCloseIpcHandle(void *provider, void *ptr,
                                           size_t size) {
    (void)provider;
    (void)ptr;
    (void)size;
    // We keep opened IPC handles in the p->hIpcMappedCache.
    // IPC handle is closed when it is evicted from the cache
    // or when cache is destroyed.
    //
    // TODO: today the size of the IPC cache is infinite.
    // When the threshold for the cache size is implemented
    // we need to introduce a reference counting mechanism.
    // The trackingOpenIpcHandle will increment the refcount for the corresponding entry.
    // The trackingCloseIpcHandle will decrement the refcount for the corresponding cache entry.
    return UMF_RESULT_SUCCESS;
}

umf_memory_provider_ops_t UMF_TRACKING_MEMORY_PROVIDER_OPS = {
    .version = UMF_PROVIDER_OPS_VERSION_CURRENT,
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
        LOG_ERR("failed, TRACKER is NULL");
        return UMF_RESULT_ERROR_UNKNOWN;
    }
    params.pool = hPool;
    params.ipcCache = critnib_new();
    if (!params.ipcCache) {
        LOG_ERR("failed to create IPC cache");
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    params.hIpcMappedCache =
        umfIpcOpenedCacheCreate(ipcOpenedCacheEvictionCallback);

    LOG_DEBUG("upstream=%p, tracker=%p, "
              "pool=%p, ipcCache=%p, hIpcMappedCache=%p",
              (void *)params.hUpstream, (void *)params.hTracker,
              (void *)params.pool, (void *)params.ipcCache,
              (void *)params.hIpcMappedCache);

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

    memset(handle, 0, sizeof(struct umf_memory_tracker_t));

    umf_ba_pool_t *alloc_info_allocator =
        umf_ba_create(sizeof(struct tracker_alloc_info_t));
    if (!alloc_info_allocator) {
        goto err_free_handle;
    }

    handle->alloc_info_allocator = alloc_info_allocator;

    void *mutex_ptr = utils_mutex_init(&handle->mutex);
    if (!mutex_ptr) {
        goto err_destroy_alloc_info_allocator;
    }

    int i;
    for (i = 0; i < MAX_LEVELS_OF_ALLOC_SEGMENT_MAP; i++) {
        handle->alloc_segments_map[i] = critnib_new();
        if (!handle->alloc_segments_map[i]) {
            goto err_destroy_mutex;
        }
    }

    LOG_DEBUG("tracker created, handle=%p, alloc_segments_map=%p",
              (void *)handle, (void *)handle->alloc_segments_map);

    return handle;

err_destroy_mutex:
    for (int j = i; j >= 0; j--) {
        if (handle->alloc_segments_map[j]) {
            critnib_delete(handle->alloc_segments_map[j]);
        }
    }
    utils_mutex_destroy_not_free(&handle->mutex);
err_destroy_alloc_info_allocator:
    umf_ba_destroy(alloc_info_allocator);
err_free_handle:
    umf_ba_global_free(handle);
    return NULL;
}

void umfMemoryTrackerDestroy(umf_memory_tracker_handle_t handle) {
    if (!handle) {
        return;
    }

    // Do not destroy the tracker if we are running in the proxy library,
    // because it may need those resources till
    // the very end of exiting the application.
    if (utils_is_running_in_proxy_lib()) {
        return;
    }

#ifndef NDEBUG
    check_if_tracker_is_empty(handle, NULL);
#endif /* NDEBUG */

    // We have to zero all inner pointers,
    // because the tracker handle can be copied
    // and used in many places.
    for (int i = 0; i < MAX_LEVELS_OF_ALLOC_SEGMENT_MAP; i++) {
        if (handle->alloc_segments_map[i]) {
            critnib_delete(handle->alloc_segments_map[i]);
            handle->alloc_segments_map[i] = NULL;
        }
    }
    utils_mutex_destroy_not_free(&handle->mutex);
    umf_ba_destroy(handle->alloc_info_allocator);
    handle->alloc_info_allocator = NULL;
    umf_ba_global_free(handle);
}
