/*
 *
 * Copyright (C) 2024-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_IPC_CACHE_H
#define UMF_IPC_CACHE_H 1

#include <umf/memory_provider.h>

#include "utils_concurrency.h"

typedef struct ipc_opened_cache_key_t {
    void *remote_base_ptr;
    umf_memory_provider_handle_t local_provider;
    int remote_pid;
} ipc_opened_cache_key_t;

typedef struct ipc_opened_cache_value_t {
    void *mapped_base_ptr;
    size_t mapped_size;
    utils_mutex_t mmap_lock;
} ipc_opened_cache_value_t;

struct ipc_opened_cache_t;

typedef struct ipc_opened_cache_t *ipc_opened_cache_handle_t;

umf_result_t umfIpcCacheGlobalInit(void);
void umfIpcCacheGlobalTearDown(void);

// define pointer to the eviction callback function
typedef void (*ipc_opened_cache_eviction_cb_t)(
    const ipc_opened_cache_key_t *key, const ipc_opened_cache_value_t *value);

ipc_opened_cache_handle_t
umfIpcOpenedCacheCreate(ipc_opened_cache_eviction_cb_t eviction_cb);

void umfIpcOpenedCacheDestroy(ipc_opened_cache_handle_t cache);

umf_result_t umfIpcOpenedCacheGet(ipc_opened_cache_handle_t cache,
                                  const ipc_opened_cache_key_t *key,
                                  uint64_t handle_id,
                                  ipc_opened_cache_value_t **retEntry);

umf_result_t
umfIpcHandleMappedCacheRelease(ipc_opened_cache_value_t *cacheValue);
#endif /* UMF_IPC_CACHE_H */
