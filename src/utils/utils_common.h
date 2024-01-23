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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#define __TLS __declspec(thread)
#else
#define __TLS __thread
#endif

#define Malloc malloc
#define Free free

static inline void *Zalloc(size_t s) {
    void *m = Malloc(s);
    if (m) {
        memset(m, 0, s);
    }
    return m;
}

#define NOFUNCTION                                                             \
    do {                                                                       \
    } while (0)
#define VALGRIND_ANNOTATE_NEW_MEMORY(p, s) NOFUNCTION
#define VALGRIND_HG_DRD_DISABLE_CHECKING(p, s) NOFUNCTION

#ifdef NDEBUG
#define ASSERT(x) NOFUNCTION
#define ASSERTne(x, y) ASSERT(x != y)
#else
#define ASSERT(x)                                                              \
    do {                                                                       \
        if (!(x)) {                                                            \
            fprintf(stderr,                                                    \
                    "Assertion failed: " #x " at " __FILE__ " line %d.\n",     \
                    __LINE__);                                                 \
            abort();                                                           \
        }                                                                      \
    } while (0)
#define ASSERTne(x, y)                                                         \
    do {                                                                       \
        long X = (x);                                                          \
        long Y = (y);                                                          \
        if (X == Y) {                                                          \
            fprintf(stderr,                                                    \
                    "Assertion failed: " #x " != " #y                          \
                    ", both are %ld, at " __FILE__ " line %d.\n",              \
                    X, __LINE__);                                              \
            abort();                                                           \
        }                                                                      \
    } while (0)
#endif

#define UMF_CHECK(condition, errorStatus)                                      \
    do {                                                                       \
        if (!(condition)) {                                                    \
            fprintf(stderr, "UMF check failed: " #condition " in %s\n",        \
                    __func__);                                                 \
            return errorStatus;                                                \
        }                                                                      \
    } while (0)

static inline size_t align_size(size_t size, size_t alignment) {
    // align size to 'alignment' bytes
    size_t rest = size & (alignment - 1);
    if (rest) {
        return (size - rest + alignment);
    } else {
        return size;
    }
}

#ifdef __cplusplus
}
#endif

#endif /* UMF_COMMON_H */
