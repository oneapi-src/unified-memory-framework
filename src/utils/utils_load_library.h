/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

/*
 * Including this header forces linking with libdl on Linux.
 */

#ifndef UMF_LOAD_LIBRARY_H
#define UMF_LOAD_LIBRARY_H 1

#ifdef _WIN32 /* Windows */

#include <windows.h>

#include <libloaderapi.h>

#else /* Linux */

#include <dlfcn.h> // forces linking with libdl on Linux

#endif /* _WIN32 */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32 /* Windows */

static inline void *util_open_library(const char *filename) {
    return LoadLibrary(TEXT(filename));
}

static inline int util_close_library(void *handle) {
    // If the FreeLibrary function succeeds, the return value is nonzero.
    // If the FreeLibrary function fails, the return value is zero.
    return (FreeLibrary(handle) == 0);
}

static inline void *util_get_symbol_addr(void *handle, const char *symbol) {
    return GetProcAddress(handle, symbol);
}

#else /* Linux */

static inline void *util_open_library(const char *filename) {
    return dlopen(filename, RTLD_LAZY);
}

static inline int util_close_library(void *handle) { return dlclose(handle); }

static inline void *util_get_symbol_addr(void *handle, const char *symbol) {
    return dlsym(handle, symbol);
}

#endif /* _WIN32 */

#ifdef __cplusplus
}
#endif

#endif /* UMF_LOAD_LIBRARY_H */
