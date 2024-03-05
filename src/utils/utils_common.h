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

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

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

#define ALIGN_UP(value, align) (((value) + (align)-1) & ~((align)-1))
#define ALIGN_DOWN(value, align) ((value) & ~((align)-1))

#define VALGRIND_ANNOTATE_NEW_MEMORY(p, s) DO_WHILE_EMPTY
#define VALGRIND_HG_DRD_DISABLE_CHECKING(p, s) DO_WHILE_EMPTY

#ifdef _WIN32 /* Windows */

#define __TLS __declspec(thread)

#else /* Linux */

#define __TLS __thread

#endif /* _WIN32 */

// utils_env_var - populate the given buffer with the value
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

// util_parse_var - Parses var for a prefix,
//                   optionally identifying a following argument.
// Parameters:
//   - var: String to parse  in "option1;option2,arg2;..." format, with options
//          separated by ';' and optional arguments by ','.
//   - option: Option to search for within var.
//   - extraArg: If not NULL, function expects an argument after the option and
//               updates this pointer to the argument's position within var.
//               If NULL, function expects option without an argument.
// Return Value:
// Pointer to option within var if found; NULL otherwise.
//
// IMPORTANT: Both extraArg and return values are pointers within var,
// and are not null-terminated.
const char *util_parse_var(const char *var, const char *option,
                           const char **extraArg);

// check if we are running in the proxy library
int util_is_running_in_proxy_lib(void);

size_t util_get_page_size(void);

char *util_strncpy(char *dest, size_t destSize, const char *src, size_t n);

// align a pointer and a size
void util_align_ptr_size(void **ptr, size_t *size, size_t alignment);

#ifdef __cplusplus
}
#endif

#endif /* UMF_COMMON_H */
