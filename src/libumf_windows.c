/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <stdlib.h>
#include <windows.h>

#include "base_alloc_global.h"
#include "provider_tracking.h"
#include "utils_log.h"

umf_memory_tracker_handle_t TRACKER = NULL;

static void umfCreate(void) {
    util_log_init();
    TRACKER = umfMemoryTrackerCreate();
}

static void umfDestroy(void) {
    umfMemoryTrackerDestroy(TRACKER);
    TRACKER = NULL;
    umf_ba_destroy_global();
}

int umf_is_destroyed(void) { return (TRACKER == NULL); }

#if defined(UMF_SHARED_LIBRARY)
BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_DETACH) {
        umfDestroy();
    } else if (fdwReason == DLL_PROCESS_ATTACH) {
        umfCreate();
    }
    return TRUE;
}

void libumfInit(void) {
    // do nothing, additional initialization not needed
}
#else
INIT_ONCE init_once_flag = INIT_ONCE_STATIC_INIT;

BOOL CALLBACK initOnceCb(PINIT_ONCE InitOnce, PVOID Parameter,
                         PVOID *lpContext) {
    umfCreate();
    atexit(umfDestroy);
    return TRACKER ? TRUE : FALSE;
}

void libumfInit(void) {
    InitOnceExecuteOnce(&init_once_flag, initOnceCb, NULL, NULL);
}
#endif
