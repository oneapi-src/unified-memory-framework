/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "critnib.h"
#include "provider_tracking.h"

#include <windows.h>

static critnib *TRACKER = NULL;

static void providerFini(void) { umfTrackingMemoryProviderFini(TRACKER); }

#if defined(UMF_SHARED_LIBRARY)
BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_DETACH) {
        providerFini();
    } else if (fdwReason == DLL_PROCESS_ATTACH) {
        TRACKER = critnib_new();
    }
    return TRUE;
}

void umfTrackingMemoryProviderInit(void) {
    // do nothing, additional initialization not needed
}
#else
INIT_ONCE init_once_flag = INIT_ONCE_STATIC_INIT;

BOOL CALLBACK providerInit(PINIT_ONCE InitOnce, PVOID Parameter,
                           PVOID *lpContext) {
    TRACKER = critnib_new();
    atexit(providerFini);
    return TRACKER ? TRUE : FALSE;
}

void umfTrackingMemoryProviderInit(void) {
    InitOnceExecuteOnce(&init_once_flag, providerInit, NULL, NULL);
}
#endif

umf_memory_tracker_handle_t umfMemoryTrackerGet(void) {
    return (umf_memory_tracker_handle_t)TRACKER;
}
