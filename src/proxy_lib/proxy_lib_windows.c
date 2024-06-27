/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <Windows.h>

#include "proxy_lib.h"

static void proxy_lib_create(void) { proxy_lib_create_common(); }

static void proxy_lib_destroy(void) { proxy_lib_destroy_common(); }

BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL;    // unused
    (void)lpvReserved; // unused

    if (fdwReason == DLL_PROCESS_DETACH) {
        proxy_lib_destroy();
    } else if (fdwReason == DLL_PROCESS_ATTACH) {
        proxy_lib_create();
    }
    return TRUE;
}
