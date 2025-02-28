/*
 *
 * Copyright (C) 2024-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <stdbool.h>

#include "base_alloc_global.h"
#include "ipc_cache.h"
#include "uthash.h"
#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_log.h"
#include "utlist.h"

// HASH_ADD macro produces `warning C4702: unreachable code` on MSVC
#ifdef _MSC_VER
#pragma warning(disable : 4702)
#endif

struct ipc_opened_cache_entry_t;

typedef struct ipc_opened_cache_entry_t *hash_map_t;
typedef struct ipc_opened_cache_entry_t *lru_list_t;

typedef struct ipc_opened_cache_entry_t {
    UT_hash_handle hh;
    struct ipc_opened_cache_entry_t *next, *prev;
    ipc_opened_cache_key_t key;
    uint64_t ref_count;
    uint64_t handle_id;
    hash_map_t
        *hash_table; // pointer to the hash table to which the entry belongs
    ipc_opened_cache_value_t value;
} ipc_opened_cache_entry_t;

typedef struct ipc_opened_cache_global_t {
    utils_mutex_t cache_lock;
    umf_ba_pool_t *cache_allocator;
    size_t max_size;
    size_t cur_size;
    lru_list_t lru_list;
} ipc_opened_cache_global_t;

typedef struct ipc_opened_cache_t {
    ipc_opened_cache_global_t *global;
    hash_map_t hash_table;
    ipc_opened_cache_eviction_cb_t eviction_cb;
} ipc_opened_cache_t;

ipc_opened_cache_global_t *IPC_OPENED_CACHE_GLOBAL = NULL;

umf_result_t umfIpcCacheGlobalInit(void) {
    umf_result_t ret = UMF_RESULT_SUCCESS;
    ipc_opened_cache_global_t *cache_global =
        umf_ba_global_alloc(sizeof(*cache_global));
    if (!cache_global) {
        LOG_ERR("Failed to allocate memory for the IPC cache global data");
        ret = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        goto err_exit;
    }

    if (NULL == utils_mutex_init(&(cache_global->cache_lock))) {
        LOG_ERR("Failed to initialize mutex for the IPC global cache");
        ret = UMF_RESULT_ERROR_UNKNOWN;
        goto err_cache_global_free;
    }

    cache_global->cache_allocator =
        umf_ba_create(sizeof(ipc_opened_cache_entry_t));
    if (!cache_global->cache_allocator) {
        LOG_ERR("Failed to create IPC cache allocator");
        ret = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        goto err_mutex_destroy;
    }

    // TODO: make max_size configurable via environment variable
    cache_global->max_size = 0;
    cache_global->cur_size = 0;
    cache_global->lru_list = NULL;

    IPC_OPENED_CACHE_GLOBAL = cache_global;
    goto err_exit;

err_mutex_destroy:
    utils_mutex_destroy_not_free(&(cache_global->cache_lock));
err_cache_global_free:
    umf_ba_global_free(cache_global);
err_exit:
    return ret;
}

#ifndef NDEBUG
static size_t getGlobalLruListSize(lru_list_t lru_list) {
    size_t size = 0;
    ipc_opened_cache_entry_t *tmp;
    DL_COUNT(lru_list, tmp, size);
    return size;
}
#endif /* NDEBUG */

void umfIpcCacheGlobalTearDown(void) {
    ipc_opened_cache_global_t *cache_global = IPC_OPENED_CACHE_GLOBAL;
    IPC_OPENED_CACHE_GLOBAL = NULL;

    if (!cache_global) {
        return;
    }

    assert(cache_global->cur_size == 0);
    assert(getGlobalLruListSize(cache_global->lru_list) == 0);

    umf_ba_destroy(cache_global->cache_allocator);
    utils_mutex_destroy_not_free(&(cache_global->cache_lock));
    umf_ba_global_free(cache_global);
}

ipc_opened_cache_handle_t
umfIpcOpenedCacheCreate(ipc_opened_cache_eviction_cb_t eviction_cb) {
    if (eviction_cb == NULL) {
        LOG_ERR("Eviction callback is NULL");
        return NULL;
    }

    ipc_opened_cache_t *cache = umf_ba_global_alloc(sizeof(*cache));

    if (!cache) {
        LOG_ERR("Failed to allocate memory for the IPC cache");
        return NULL;
    }

    assert(IPC_OPENED_CACHE_GLOBAL != NULL);

    cache->global = IPC_OPENED_CACHE_GLOBAL;
    cache->hash_table = NULL;
    cache->eviction_cb = eviction_cb;

    return cache;
}

void umfIpcOpenedCacheDestroy(ipc_opened_cache_handle_t cache) {
    ipc_opened_cache_entry_t *entry, *tmp;

    utils_mutex_lock(&(cache->global->cache_lock));
    HASH_ITER(hh, cache->hash_table, entry, tmp) {
        DL_DELETE(cache->global->lru_list, entry);
        HASH_DEL(cache->hash_table, entry);
        cache->global->cur_size -= 1;
        cache->eviction_cb(&entry->key, &entry->value);
        utils_mutex_destroy_not_free(&(entry->value.mmap_lock));
        umf_ba_free(cache->global->cache_allocator, entry);
    }
    HASH_CLEAR(hh, cache->hash_table);
    utils_mutex_unlock(&(cache->global->cache_lock));

    umf_ba_global_free(cache);
}

umf_result_t umfIpcOpenedCacheGet(ipc_opened_cache_handle_t cache,
                                  const ipc_opened_cache_key_t *key,
                                  uint64_t handle_id,
                                  ipc_opened_cache_value_t **retEntry) {
    ipc_opened_cache_entry_t *entry = NULL;
    umf_result_t ret = UMF_RESULT_SUCCESS;
    bool evicted = false;
    ipc_opened_cache_value_t evicted_value;

    if (!cache || !key || !retEntry) {
        LOG_ERR("Some arguments are NULL, cache=%p, key=%p, retEntry=%p",
                (void *)cache, (const void *)key, (void *)retEntry);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    assert(cache->global != NULL);

    utils_mutex_lock(&(cache->global->cache_lock));

    HASH_FIND(hh, cache->hash_table, key, sizeof(*key), entry);
    if (entry && entry->handle_id == handle_id) { // cache hit
        // update frequency list
        // remove the entry from the current position
        DL_DELETE(cache->global->lru_list, entry);
        // add the entry to the head of the list
        DL_PREPEND(cache->global->lru_list, entry);
    } else { //cache miss
        // Look for eviction candidate
        if (entry == NULL && cache->global->max_size != 0 &&
            cache->global->cur_size >= cache->global->max_size) {
            // If max_size is set and the cache is full, evict the least recently used entry.
            entry = cache->global->lru_list->prev;
        }

        if (entry) { // we have eviction candidate
            // remove the entry from the frequency list
            DL_DELETE(cache->global->lru_list, entry);
            // remove the entry from the hash table it belongs to
            HASH_DEL(*(entry->hash_table), entry);
            cache->global->cur_size -= 1;
            evicted_value.mapped_base_ptr = entry->value.mapped_base_ptr;
            evicted_value.mapped_size = entry->value.mapped_size;
            evicted = true;
        } else { // allocate the new entry
            entry = umf_ba_alloc(cache->global->cache_allocator);
            if (!entry) {
                ret = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
                LOG_ERR("Failed to allocate memory for a new IPC cache entry");
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
        entry->hash_table = &cache->hash_table;
        entry->value.mapped_size = 0;
        entry->value.mapped_base_ptr = NULL;

        HASH_ADD(hh, cache->hash_table, key, sizeof(entry->key), entry);
        DL_PREPEND(cache->global->lru_list, entry);
        cache->global->cur_size += 1;
    }

exit:
    if (ret == UMF_RESULT_SUCCESS) {
        utils_atomic_increment_u64(&entry->ref_count);
        *retEntry = &entry->value;
    }

    utils_mutex_unlock(&(cache->global->cache_lock));

    if (evicted) {
        cache->eviction_cb(key, &evicted_value);
    }

    return ret;
}
