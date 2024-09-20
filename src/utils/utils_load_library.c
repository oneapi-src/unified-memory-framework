/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifdef _WIN32

// Include "windows.h" first to ensure that all necessary types and function prototypes
// are available to other system headers that depend on it, such as "libloaderapi.h".
// clang-format off
#include <windows.h>
#include <libloaderapi.h>
// clang-format on

#else

#define _GNU_SOURCE 1

#include <dlfcn.h> // forces linking with libdl on Linux

#endif

#include "utils_load_library.h"

#ifdef _WIN32

void *utils_open_library(const char *filename, int userFlags) {
    (void)userFlags; //unused for win
    return LoadLibrary(TEXT(filename));
}

int utils_close_library(void *handle) {
    // If the FreeLibrary function succeeds, the return value is nonzero.
    // If the FreeLibrary function fails, the return value is zero.
    return (FreeLibrary((HMODULE)handle) == 0);
}

void *utils_get_symbol_addr(void *handle, const char *symbol,
                            const char *libname) {
    if (!handle) {
        if (libname == NULL) {
            return NULL;
        }
        handle = GetModuleHandle(libname);
    }
    return (void *)GetProcAddress((HMODULE)handle, symbol);
}

#else /* Linux */

void *utils_open_library(const char *filename, int userFlags) {
    int dlopenFlags = RTLD_LAZY;
    if (userFlags & UMF_UTIL_OPEN_LIBRARY_GLOBAL) {
        dlopenFlags |= RTLD_GLOBAL;
    }
    return dlopen(filename, dlopenFlags);
}

int utils_close_library(void *handle) { return dlclose(handle); }

void *utils_get_symbol_addr(void *handle, const char *symbol,
                            const char *libname) {
    (void)libname; //unused
    if (!handle) {
        handle = RTLD_DEFAULT;
    }
    return dlsym(handle, symbol);
}

#endif
