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

#ifdef __cplusplus
extern "C" {
#endif
#define UMF_UTIL_OPEN_LIBRARY_GLOBAL 1

void *util_open_library(const char *filename, int userFlags);
int util_close_library(void *handle);
void *util_get_symbol_addr(void *handle, const char *symbol,
                           const char *libname);

#ifdef __cplusplus
}
#endif

#endif /* UMF_LOAD_LIBRARY_H */
