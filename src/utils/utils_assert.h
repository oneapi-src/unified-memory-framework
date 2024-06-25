/*
 *
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_ASSERT_H
#define UMF_ASSERT_H 1

#include "utils_log.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NOFUNCTION                                                             \
    do {                                                                       \
    } while (0)

#ifdef NDEBUG
#define ASSERT(x) NOFUNCTION
#define ASSERTne(x, y) NOFUNCTION
#else
#define ASSERT(x)                                                              \
    do {                                                                       \
        if (!(x)) {                                                            \
            LOG_FATAL("Assertion failed: " #x " at " __FILE__ " line %d.",     \
                      __LINE__);                                               \
            abort();                                                           \
        }                                                                      \
    } while (0)
#define ASSERTne(x, y)                                                         \
    do {                                                                       \
        long X = (x);                                                          \
        long Y = (y);                                                          \
        if (X == Y) {                                                          \
            LOG_FATAL("Assertion failed: " #x " != " #y                        \
                      ", both are %ld, at " __FILE__ " line %d.",              \
                      X, __LINE__);                                            \
            abort();                                                           \
        }                                                                      \
    } while (0)
#endif

#define UMF_CHECK(condition, errorStatus)                                      \
    do {                                                                       \
        if (!(condition)) {                                                    \
            LOG_FATAL("UMF check failed: " #condition " in %s", __func__);     \
            return errorStatus;                                                \
        }                                                                      \
    } while (0)

#define COMPILE_ERROR_ON(cond) ((void)sizeof(char[(cond) ? -1 : 1]))

#ifdef __cplusplus
}
#endif

#endif /* UMF_ASSERT_H */
