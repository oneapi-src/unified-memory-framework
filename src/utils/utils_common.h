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

#else /* Linux */

#define __TLS __thread

#endif /* _WIN32 */

// util_env_var - populate the given buffer with the value
//                of the given environment variable
// Return value
// If the function succeeds, the return value is the number of characters
// stored in the buffer pointed to by buffer, not including
// the terminating null character.
//
// If the buffer is not large enough to hold the data, then:
// 1) the return value equals (-1) * the buffer size (in characters)
//    required to hold the string and its terminating null character,
// 2) the content of the buffer is undefined.
//
// If the function fails, the return value is zero.
int util_env_var(const char *envvar, char *buffer, size_t buffer_size);

// Check if the environment variable contains the given string.
int util_env_var_has_str(const char *envvar, const char *str);

// check if we are running in the proxy library
static inline int is_running_in_proxy_lib(void) {
    return util_env_var_has_str("LD_PRELOAD", "libumf_proxy.so");
}

size_t util_get_page_size(void);
char *util_strncpy(char *dest, size_t destSize, const char *src, size_t n);

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
