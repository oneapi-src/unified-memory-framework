/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <stddef.h>

#include "base_alloc_global.h"
#include "ipc_cache.h"
#include "memspace_internal.h"
#include "provider_tracking.h"
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
        umf_result_t umf_result = umfIpcCacheGlobalInit();
        if (umf_result != UMF_RESULT_SUCCESS) {
            LOG_ERR("Failed to initialize IPC cache");
            return -1;
        }
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
        // make sure TRACKER is not used after being destroyed
        umf_memory_tracker_handle_t t = TRACKER;
        TRACKER = NULL;
        umfMemoryTrackerDestroy(t);

        umf_ba_destroy_global();
    }
}

int umfGetCurrentVersion(void) { return UMF_VERSION_CURRENT; }
