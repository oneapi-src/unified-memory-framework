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
#include "memspace_host_all_internal.h"
#include "provider_tracking.h"

umf_memory_tracker_handle_t TRACKER = NULL;

void __attribute__((constructor(102))) umfCreate(void) {
    TRACKER = umfMemoryTrackerCreate();
}

void __attribute__((destructor(102))) umfDestroy(void) {
    umf_memory_tracker_handle_t t = TRACKER;
    // make sure TRACKER is not used after being destroyed
    TRACKER = NULL;
    umfMemoryTrackerDestroy(t);

#if defined(UMF_BUILD_OS_MEMORY_PROVIDER)
    umfMemspaceHostAllDestroy();
#endif
}

void libumfInit(void) {
    // do nothing, additional initialization not needed
}
