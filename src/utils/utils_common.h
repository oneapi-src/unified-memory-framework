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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DO_WHILE_EMPTY                                                         \
    do {                                                                       \
    } while (0)
#define DO_WHILE_EXPRS(expression)                                             \
    do {                                                                       \
        expression;                                                            \
    } while (0)

#ifdef _WIN32 /* Windows */

#define __TLS __declspec(thread)

static inline char *util_getenv(const char *name) {
    char *buffer;
    size_t numberOfElements;
    errno_t err = _dupenv_s(&buffer, &numberOfElements, name);
    if (err) {
        return NULL;
    }

    return buffer;
}

static inline void util_free_getenv(char *val) { free(val); }

#else /* Linux */

#define __TLS __thread

static inline char *util_getenv(const char *name) { return getenv(name); }
static inline void util_free_getenv(const char *val) {
    (void)val; // unused
}

#endif /* _WIN32 */

// check if we are running in the proxy library
static inline int is_running_in_proxy_lib(void) {
    int is_in_proxy_lib_val = 0;
    char *ld_preload = util_getenv("LD_PRELOAD");
    if (ld_preload && strstr(ld_preload, "libumf_proxy.so")) {
        is_in_proxy_lib_val = 1;
    }

    util_free_getenv(ld_preload);
    return is_in_proxy_lib_val;
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

// align a pointer and a size
static inline void align_ptr_size(void **ptr, size_t *size, size_t alignment) {
    uintptr_t p = (uintptr_t)*ptr;
    size_t s = *size;

    // align pointer to 'alignment' bytes and adjust the size
    size_t rest = p & (alignment - 1);
    if (rest) {
        p += alignment - rest;
        s -= alignment - rest;
    }

    ASSERT((p & (alignment - 1)) == 0);
    ASSERT((s & (alignment - 1)) == 0);

    *ptr = (void *)p;
    *size = s;
}

#define ALIGN_UP(value, align) (((value) + (align)-1) & ~((align)-1))
#define ALIGN_DOWN(value, align) ((value) & ~((align)-1))

#ifdef __cplusplus
}
#endif

#endif /* UMF_COMMON_H */
