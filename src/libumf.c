/*
 *
 * Copyright (C) 2024-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <stddef.h>

#include "base_alloc_global.h"
#include "ipc_cache.h"
#include "memspace_internal.h"
#include "provider_cuda_internal.h"
#include "provider_level_zero_internal.h"
#include "provider_tracking.h"
#include "utils_common.h"
#include "utils_log.h"
#if !defined(UMF_NO_HWLOC)
#include "topology.h"
#endif

umf_memory_tracker_handle_t TRACKER = NULL;

static unsigned long long umfRefCount = 0;

int umfInit(void) {
    if (utils_fetch_and_add64(&umfRefCount, 1) == 0) {
        utils_log_init();
        TRACKER = umfMemoryTrackerCreate();
        if (!TRACKER) {
            LOG_ERR("Failed to create memory tracker");
            return -1;
        }

        LOG_DEBUG("UMF tracker created");

        umf_result_t umf_result = umfIpcCacheGlobalInit();
        if (umf_result != UMF_RESULT_SUCCESS) {
            LOG_ERR("Failed to initialize IPC cache");
            return -1;
        }

        LOG_DEBUG("UMF IPC cache initialized");
    }

    if (TRACKER) {
        LOG_DEBUG("UMF library initialized");
    }

    return 0;
}

void umfTearDown(void) {
    if (utils_fetch_and_add64(&umfRefCount, -1) == 1) {
#if !defined(_WIN32) && !defined(UMF_NO_HWLOC)
        umfMemspaceHostAllDestroy();
        umfMemspaceHighestCapacityDestroy();
        umfMemspaceHighestBandwidthDestroy();
        umfMemspaceLowestLatencyDestroy();
        umfDestroyTopology();
#endif
        umfIpcCacheGlobalTearDown();

        if (utils_is_running_in_proxy_lib_with_size_threshold()) {
            // We cannot destroy the TRACKER nor the base allocator
            // when we are running in the proxy library with a size threshold,
            // because it could result in calling the system free()
            // with an invalid pointer and a segfault.
            goto fini_umfTearDown;
        }

        // make sure TRACKER is not used after being destroyed
        umf_memory_tracker_handle_t t = TRACKER;
        TRACKER = NULL;
        umfMemoryTrackerDestroy(t);
        LOG_DEBUG("UMF tracker destroyed");

        umf_ba_destroy_global();
        LOG_DEBUG("UMF base allocator destroyed");

    fini_umfTearDown:
        fini_ze_global_state();
        fini_cu_global_state();
        LOG_DEBUG("UMF library finalized");
    }
}

int umfGetCurrentVersion(void) { return UMF_VERSION_CURRENT; }
