/*
 *
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_LIBUMF_H
#define UMF_LIBUMF_H 1

#ifdef __cplusplus
extern "C" {
#endif

// initializes runtime state needed by the library (needed mostly for static libraries on Windows)
void libumfInit(void);

#ifdef __cplusplus
}
#endif

#endif /* UMF_LIBUMF_H */
