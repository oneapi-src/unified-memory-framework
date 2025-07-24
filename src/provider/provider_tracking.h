/*
 *
 * Copyright (C) 2023-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_MEMORY_TRACKER_INTERNAL_H
#define UMF_MEMORY_TRACKER_INTERNAL_H 1

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>

#include <umf/base.h>
#include <umf/memory_pool.h>
#include <umf/memory_provider.h>

#include "base_alloc.h"
#include "critnib.h"
#include "memory_props_internal.h"
#include "utils_concurrency.h"

#ifdef __cplusplus
extern "C" {
#endif

struct umf_memory_tracker_t;
typedef struct umf_memory_tracker_t *umf_memory_tracker_handle_t;

extern umf_memory_tracker_handle_t TRACKER;

umf_result_t umfMemoryTrackerCreate(umf_memory_tracker_handle_t *handle);
void umfMemoryTrackerDestroy(umf_memory_tracker_handle_t handle);

typedef struct tracker_alloc_info_t {
    umf_memory_properties_t props;

    // number of overlapping memory regions in the next level of map falling
    // within the current range
    size_t n_children;
#if !defined(NDEBUG) && defined(UMF_DEVELOPER_MODE)
    uint64_t is_freed;
#endif
} tracker_alloc_info_t;

umf_result_t umfMemoryTrackerGetAllocInfo(const void *ptr,
                                          tracker_alloc_info_t **info);

typedef struct umf_ipc_info_t {
    umf_memory_properties_handle_t props;

    void *base;
    size_t baseSize;
    umf_memory_provider_handle_t provider;
} umf_ipc_info_t;

umf_result_t umfMemoryTrackerGetIpcInfo(const void *ptr,
                                        umf_ipc_info_t *pIpcInfo);

// Creates a memory provider that tracks each allocation/deallocation through umf_memory_tracker_handle_t and
// forwards all requests to hUpstream memory Provider. hUpstream lifetime should be managed by the user of this function.
umf_result_t umfTrackingMemoryProviderCreate(
    umf_memory_provider_handle_t hUpstream, umf_memory_pool_handle_t hPool,
    umf_memory_provider_handle_t *hTrackingProvider);

void umfTrackingMemoryProviderGetUpstreamProvider(
    umf_memory_provider_handle_t hTrackingProvider,
    umf_memory_provider_handle_t *hUpstream);

#ifdef __cplusplus
}
#endif

#endif /* UMF_MEMORY_TRACKER_INTERNAL_H */
