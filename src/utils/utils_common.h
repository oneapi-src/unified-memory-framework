/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_COMMON_H
#define UMF_COMMON_H 1

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#define __TLS __declspec(thread)
#else
#define __TLS __thread
#endif

#ifdef __cplusplus
}
#endif

#endif /* UMF_COMMON_H */
