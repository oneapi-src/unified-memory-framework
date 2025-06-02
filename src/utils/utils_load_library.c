/*
 *
 * Copyright (C) 2024-2025 Intel Corporation
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
// #include <winnt.h>
#include <libloaderapi.h>
// clang-format on

#else // _WIN32

#define _GNU_SOURCE 1

#include <dlfcn.h> // forces linking with libdl on Linux

#endif // !_WIN32

#include <stddef.h>

#include "utils_load_library.h"
#include "utils_log.h"

#ifdef _WIN32

void *utils_open_library(const char *filename, int userFlags) {
    if (userFlags & UMF_UTIL_OPEN_LIBRARY_NO_LOAD) {
        HMODULE hModule;
        // BOOL ret = GetModuleHandleEx(0, TEXT(filename), &hModule);
        BOOL ret = GetModuleHandleEx(0, filename, &hModule);
        return ret ? hModule : NULL;
    }
    // return LoadLibrary(TEXT(filename));
    return LoadLibrary(filename);
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

    void *addr = (void *)GetProcAddress((HMODULE)handle, symbol);
    if (addr == NULL) {
        LOG_ERR("Required symbol not found: %s", symbol);
    }

    return addr;
}

#else /* Linux */

void *utils_open_library(const char *filename, int userFlags) {
    int dlopenFlags = RTLD_LAZY;
    if (userFlags & UMF_UTIL_OPEN_LIBRARY_GLOBAL) {
        dlopenFlags |= RTLD_GLOBAL;
    }
    if (userFlags & UMF_UTIL_OPEN_LIBRARY_NO_LOAD) {
        dlopenFlags |= RTLD_NOLOAD;
    }

    void *handle = dlopen(filename, dlopenFlags);
    if (handle == NULL) {
        LOG_FATAL("dlopen(%s) failed with error: %s", filename, dlerror());
    }

    return handle;
}

int utils_close_library(void *handle) { return dlclose(handle); }

void *utils_get_symbol_addr(void *handle, const char *symbol,
                            const char *libname) {
    (void)libname; //unused
    if (!handle) {
        handle = RTLD_DEFAULT;
    }

    void *addr = dlsym(handle, symbol);
    if (addr == NULL) {
        LOG_ERR("required symbol not found: %s (error: %s)", symbol, dlerror());
    }

    return addr;
}

#endif
