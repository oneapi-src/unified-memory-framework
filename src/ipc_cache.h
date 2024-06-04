/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_IPC_CACHE_H
#define UMF_IPC_CACHE_H 1

#include "umf/memory_provider.h"

#include "base_alloc.h"
#include "uthash.h"
#include "utils_concurrency.h"

typedef struct ipc_mapped_handle_cache_key_t {
    void *remote_base_ptr;
    umf_memory_provider_handle_t local_provider;
    int remote_pid;
} ipc_mapped_handle_cache_key_t;

typedef struct ipc_mapped_handle_cache_value_t {
    void *mapped_base_ptr;
    size_t mapped_size;
    utils_mutex_t mmap_lock;
} ipc_mapped_handle_cache_value_t;

struct ipc_handle_mapped_cache_t;

typedef struct ipc_handle_mapped_cache_t *ipc_handle_mapped_cache_handle_t;

void umfIpcCacheInit(void);
void umfIpcCacheTearDown(void);

// define pointer to the eviction callback function
typedef void (*ipc_handle_mapped_cache_eviction_cb_t)(
    const ipc_mapped_handle_cache_key_t *key,
    const ipc_mapped_handle_cache_value_t *value);

ipc_handle_mapped_cache_handle_t umfIpcHandleMappedCacheCreate(
    ipc_handle_mapped_cache_eviction_cb_t eviction_cb);

void umfIpcHandleMappedCacheDestroy(ipc_handle_mapped_cache_handle_t cache);

umf_result_t
umfIpcHandleMappedCacheGet(ipc_handle_mapped_cache_handle_t cache,
                           const ipc_mapped_handle_cache_key_t *key,
                           uint64_t handle_id,
                           ipc_mapped_handle_cache_value_t **retEntry);

#endif /* UMF_IPC_CACHE_H */
