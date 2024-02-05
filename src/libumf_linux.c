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
#include "provider_tracking.h"

umf_memory_tracker_handle_t TRACKER = NULL;

void __attribute__((constructor)) umfCreate(void) {
    TRACKER = umfMemoryTrackerCreate();
    umf_ba_create_global();
}

void __attribute__((destructor)) umfDestroy(void) {
    umf_ba_destroy_global();
    umfMemoryTrackerDestroy(TRACKER);
}

void libumfInit(void) {
    // do nothing, additional initialization not needed
}
