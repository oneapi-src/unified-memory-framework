/*
 *
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

/*
 The project uses GTEST framework for testing, which is not supported in C
 These asserts should NOT be used in other purposes than for testing C API 
 */

#ifndef UMF_TEST_UT_ASSERTS_H
#define UMF_TEST_UT_ASSERTS_H 1

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

static inline void UT_FATAL(const char *format, ...) {
    va_list args_list;
    va_start(args_list, format);
    vfprintf(stderr, format, args_list);
    va_end(args_list);

    fprintf(stderr, "\n");

    abort();
}

static inline void UT_OUT(const char *format, ...) {
    va_list args_list;
    va_start(args_list, format);
    vfprintf(stdout, format, args_list);
    va_end(args_list);

    fprintf(stdout, "\n");
}

// Assert a condition is true at runtime
#define UT_ASSERT(cnd)                                                         \
    ((void)((cnd) || (UT_FATAL("%s:%d %s - assertion failure: %s", __FILE__,   \
                               __LINE__, __func__, #cnd),                      \
                      0)))

// Assertion with extra info printed if assertion fails at runtime
#define UT_ASSERTinfo(cnd, info)                                               \
    ((void)((cnd) ||                                                           \
            (UT_FATAL("%s:%d %s - assertion failure: %s (%s = %s)", __FILE__,  \
                      __LINE__, __func__, #cnd, #info, info),                  \
             0)))

// Assert two integer values are equal at runtime
#define UT_ASSERTeq(lhs, rhs)                                                  \
    ((void)(((lhs) == (rhs)) ||                                                \
            (UT_FATAL("%s:%d %s - assertion failure: %s (0x%llx) == %s "       \
                      "(0x%llx)",                                              \
                      __FILE__, __LINE__, __func__, #lhs,                      \
                      (unsigned long long)(lhs), #rhs,                         \
                      (unsigned long long)(rhs)),                              \
             0)))

// Assert two integer values are not equal at runtime
#define UT_ASSERTne(lhs, rhs)                                                  \
    ((void)(((lhs) != (rhs)) ||                                                \
            (UT_FATAL("%s:%d %s - assertion failure: %s (0x%llx) != %s "       \
                      "(0x%llx)",                                              \
                      __FILE__, __LINE__, __func__, #lhs,                      \
                      (unsigned long long)(lhs), #rhs,                         \
                      (unsigned long long)(rhs)),                              \
             0)))

#endif /* UMF_TEST_UT_ASSERTS_H */
