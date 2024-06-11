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
#include "memspace_internal.h"
#include "provider_tracking.h"
#include "topology.h"
#include "utils_log.h"

umf_memory_tracker_handle_t TRACKER = NULL;

static unsigned long long umfRefCount = 0;

int umfInit(void) {
    if (util_fetch_and_add64(&umfRefCount, 1) == 0) {
        util_log_init();
        TRACKER = umfMemoryTrackerCreate();
    }

    return (TRACKER) ? 0 : -1;
}

void umfTearDown(void) {
    if (util_fetch_and_add64(&umfRefCount, -1) == 1) {
#ifndef _WIN32
        umfMemspaceHostAllDestroy();
        umfMemspaceHighestCapacityDestroy();
        umfMemspaceHighestBandwidthDestroy();
        umfMemspaceLowestLatencyDestroy();
        umfDestroyTopology();
#endif
        // make sure TRACKER is not used after being destroyed
        umf_memory_tracker_handle_t t = TRACKER;
        TRACKER = NULL;
        umfMemoryTrackerDestroy(t);

        umf_ba_destroy_global();
    }
}
