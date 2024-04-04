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

void __attribute__((constructor)) umfCreate(void) {
    util_log_init();
    TRACKER = umfMemoryTrackerCreate();
}

void __attribute__((destructor)) umfDestroy(void) {
    umf_memory_tracker_handle_t t = TRACKER;
    // make sure TRACKER is not used after being destroyed
    TRACKER = NULL;
    umfMemoryTrackerDestroy(t);
    umfMemspaceHostAllDestroy();
    umfMemspaceHighestCapacityDestroy();
    umfMemspaceHighestBandwidthDestroy();
    umfDestroyTopology();
}

void libumfInit(void) {
    // do nothing, additional initialization not needed
}
