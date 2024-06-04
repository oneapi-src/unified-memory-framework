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

struct ipc_handle_cache_entry_t;

typedef struct ipc_handle_cache_entry_t *hash_map_t;
typedef struct ipc_handle_cache_entry_t *lru_list_t;

typedef struct ipc_handle_cache_entry_t {
    UT_hash_handle hh;
    struct ipc_handle_cache_entry_t *next, *prev;
    ipc_mapped_handle_cache_key_t key;
    uint64_t ref_count;
    uint64_t handle_id;
    hash_map_t
        *hash_table; // pointer to the hash table to which the entry belongs
    ipc_mapped_handle_cache_value_t value;
} ipc_handle_cache_entry_t;

typedef struct ipc_handle_mapped_cache_global_t {
    utils_mutex_t cache_lock;
    umf_ba_pool_t *cache_allocator;
    size_t max_size;
    size_t cur_size;
    lru_list_t lru_list;
} ipc_handle_mapped_cache_global_t;

typedef struct ipc_handle_mapped_cache_t {
    ipc_handle_mapped_cache_global_t *global;
    hash_map_t hash_table;
    ipc_handle_mapped_cache_eviction_cb_t eviction_cb;
} ipc_handle_mapped_cache_t;

ipc_handle_mapped_cache_global_t *IPC_MAPPED_CACHE_GLOBAL = NULL;

void umfIpcCacheInit(void) {
    ipc_handle_mapped_cache_global_t *cache_global =
        umf_ba_global_alloc(sizeof(*cache_global));
    if (!cache_global) {
        return;
    }

    if (NULL == utils_mutex_init(&(cache_global->cache_lock))) {
        LOG_ERR("Failed to initialize mutex for the IPC cache");
        umf_ba_global_free(cache_global);
        return;
    }

    cache_global->cache_allocator =
        umf_ba_create(sizeof(ipc_handle_cache_entry_t));
    if (!cache_global->cache_allocator) {
        LOG_ERR("Failed to create IPC cache allocator");
        umf_ba_global_free(cache_global);
        return;
    }

    cache_global->max_size = 0;
    cache_global->cur_size = 0;
    cache_global->lru_list = NULL;

    IPC_MAPPED_CACHE_GLOBAL = cache_global;
}

static size_t getGlobalLruListSize(lru_list_t lru_list) {
    size_t size = 0;
    ipc_handle_cache_entry_t *tmp;
    DL_COUNT(lru_list, tmp, size);
    return size;
}

void umfIpcCacheTearDown(void) {
    ipc_handle_mapped_cache_global_t *cache_global = IPC_MAPPED_CACHE_GLOBAL;
    IPC_MAPPED_CACHE_GLOBAL = NULL;

    if (!cache_global) {
        return;
    }

    assert(cache_global->cur_size == 0);
    assert(getGlobalLruListSize(cache_global->lru_list) == 0);

    umf_ba_destroy(cache_global->cache_allocator);
    umf_ba_global_free(cache_global);
}

ipc_handle_mapped_cache_handle_t umfIpcHandleMappedCacheCreate(
    ipc_handle_mapped_cache_eviction_cb_t eviction_cb) {
    ipc_handle_mapped_cache_t *cache = umf_ba_global_alloc(sizeof(*cache));

    if (!cache) {
        return NULL;
    }

    cache->global = IPC_MAPPED_CACHE_GLOBAL;
    cache->hash_table = NULL;
    cache->eviction_cb = eviction_cb;

    return cache;
}

void umfIpcHandleMappedCacheDestroy(ipc_handle_mapped_cache_handle_t cache) {
    ipc_handle_cache_entry_t *entry, *tmp;
    HASH_ITER(hh, cache->hash_table, entry, tmp) {
        DL_DELETE(cache->global->lru_list, entry);
        HASH_DEL(cache->hash_table, entry);
        cache->global->cur_size -= 1;
        cache->eviction_cb(&entry->key, &entry->value);
        umf_ba_free(cache->global->cache_allocator, entry);
    }
    HASH_CLEAR(hh, cache->hash_table);

    umf_ba_global_free(cache);
}

umf_result_t
umfIpcHandleMappedCacheGet(ipc_handle_mapped_cache_handle_t cache,
                           const ipc_mapped_handle_cache_key_t *key,
                           uint64_t handle_id,
                           ipc_mapped_handle_cache_value_t **retEntry) {
    ipc_handle_cache_entry_t *entry = NULL;
    umf_result_t ret = UMF_RESULT_SUCCESS;
    bool evicted = false;
    ipc_mapped_handle_cache_value_t evicted_value;

    if (!cache) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    utils_mutex_lock(&(cache->global->cache_lock));

    HASH_FIND(hh, cache->hash_table, key, sizeof(*key), entry);
    if (entry && entry->handle_id == handle_id) { // cache hit
        // update frequency list
        DL_DELETE(cache->global->lru_list, entry);
        DL_PREPEND(cache->global->lru_list, entry);
    } else { //cache miss
        // Look for eviction candidate
        if (entry == NULL && cache->global->max_size != 0 &&
            cache->global->cur_size >= cache->global->max_size) {
            entry = cache->global->lru_list->prev;
        }

        if (entry) { // we have eviction candidate
            DL_DELETE(cache->global->lru_list, entry);
            HASH_DEL(*(entry->hash_table), entry);
            cache->global->cur_size -= 1;
            evicted_value.mapped_base_ptr = entry->value.mapped_base_ptr;
            evicted_value.mapped_size = entry->value.mapped_size;
            evicted = true;
        } else {
            entry = umf_ba_alloc(cache->global->cache_allocator);
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
        entry->hash_table = &cache->hash_table;
        entry->value.mapped_size = 0;
        entry->value.mapped_base_ptr = NULL;

        HASH_ADD(hh, cache->hash_table, key, sizeof(entry->key), entry);
        DL_PREPEND(cache->global->lru_list, entry);
        cache->global->cur_size += 1;
    }

exit:
    if (ret == UMF_RESULT_SUCCESS) {
        utils_atomic_increment(&entry->ref_count);
        *retEntry = &entry->value;
    }

    utils_mutex_unlock(&(cache->global->cache_lock));

    if (evicted) {
        cache->eviction_cb(key, &evicted_value);
    }

    return ret;
}
