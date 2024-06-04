/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */
#include "ipc_cache.h"

#include <stdbool.h>

#include "base_alloc_global.h"
#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_log.h"
#include "utlist.h"

ipc_handle_mmaped_cache_handle_t umfIpcHandleMmapedCacheCreate(void) {
    ipc_handle_mmaped_cache_t *cache = umf_ba_global_alloc(sizeof(*cache));
    if (!cache) {
        return NULL;
    }

    if (NULL == utils_mutex_init(&(cache->cache_lock))) {
        LOG_ERR("Failed to initialize mutex for the IPC cache");
        umf_ba_global_free(cache);
        return NULL;
    }

    cache->cache_allocator = umf_ba_create(sizeof(ipc_handle_cache_entry_t));
    if (!cache->cache_allocator) {
        LOG_ERR("Failed to create IPC cache allocator");
        umf_ba_global_free(cache);
        return NULL;
    }

    cache->max_size = 0;
    cache->cur_size = 0;
    cache->hash_table = NULL;
    cache->frequency_list = NULL;

    return cache;
}

void umfIpcHandleMmapedCacheDestroy(ipc_handle_mmaped_cache_handle_t cache) {
    if (!cache) {
        return;
    }

    ipc_handle_cache_entry_t *entry, *tmp;
    HASH_ITER(hh, cache->hash_table, entry, tmp) {
        DL_DELETE(cache->frequency_list, entry);
        HASH_DEL(cache->hash_table, entry);
        cache->cur_size -= 1;
        umf_ba_free(cache->cache_allocator, entry);
    }
    HASH_CLEAR(hh, cache->hash_table);

    umf_ba_destroy(cache->cache_allocator);
    umf_ba_global_free(cache);
}

umf_result_t
umfIpcHandleMmapedCacheGet(ipc_handle_mmaped_cache_handle_t cache,
                           const ipc_mmaped_handle_cache_key_t *key,
                           uint64_t handle_id,
                           ipc_handle_mmaped_cache_eviction_cb_t eviction_cb,
                           ipc_mmaped_handle_cache_value_t **retEntry) {
    ipc_handle_cache_entry_t *entry = NULL;
    umf_result_t ret = UMF_RESULT_SUCCESS;
    bool evicted = false;
    ipc_mmaped_handle_cache_value_t evicted_value;

    if (!cache) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    utils_mutex_lock(&(cache->cache_lock));

    HASH_FIND(hh, cache->hash_table, key, sizeof(*key), entry);
    if (entry && entry->handle_id == handle_id) { // cache hit
        // update frequency list
        DL_DELETE(cache->frequency_list, entry);
        DL_PREPEND(cache->frequency_list, entry);
    } else { //cache miss
        // Look for eviction candidate
        if (entry == NULL && cache->max_size != 0 &&
            cache->cur_size >= cache->max_size) {
            entry = cache->frequency_list->prev;
        }

        if (entry) { // we have eviction candidate
            DL_DELETE(cache->frequency_list, entry);
            HASH_DEL(cache->hash_table, entry);
            cache->cur_size -= 1;
            evicted_value.mmaped_base_ptr = entry->value.mmaped_base_ptr;
            evicted_value.mmaped_size = entry->value.mmaped_size;
            evicted = true;
        } else {
            entry = umf_ba_alloc(cache->cache_allocator);
            if (!entry) {
                ret = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
                goto exit;
            }
            if (NULL == utils_mutex_init(&(entry->value.mmap_lock))) {
                LOG_ERR("Failed to initialize mutex for the IPC cache entry");
                umf_ba_global_free(entry);
                ret = UMF_RESULT_ERROR_UNKNOWN;
                goto exit;
            }
        }

        entry->key = *key;
        entry->ref_count = 0;
        entry->handle_id = handle_id;
        entry->value.mmaped_size = 0;
        entry->value.mmaped_base_ptr = NULL;

        HASH_ADD(hh, cache->hash_table, key, sizeof(entry->key), entry);
        DL_PREPEND(cache->frequency_list, entry);
        cache->cur_size += 1;
    }

exit:
    if (ret == UMF_RESULT_SUCCESS) {
        utils_atomic_increment(&entry->ref_count);
        *retEntry = &entry->value;
    }

    utils_mutex_unlock(&(cache->cache_lock));

    if (evicted) {
        eviction_cb(key, &evicted_value);
    }

    return ret;
}
