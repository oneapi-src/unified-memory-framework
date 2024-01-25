// Copyright (C) 2023-2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// This file contains helpers for tests for UMF pool API

#ifndef UMF_TEST_HELPERS_H
#define UMF_TEST_HELPERS_H 1

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <umf/base.h>
#include <umf/memory_pool.h>
#include <umf/memory_provider_ops.h>

#ifdef __cplusplus
extern "C" {
#endif

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

#define ALIGN_UP(size, align) (((size) + (align)-1) & ~((align)-1))

int bufferIsFilledWithChar(void *ptr, size_t size, char c);

int buffersHaveSameContent(void *first, void *second, size_t size);

int addressIsAligned(void *ptr, size_t alignment);

umf_memory_provider_handle_t nullProviderCreate(void);

umf_memory_provider_handle_t
traceProviderCreate(umf_memory_provider_handle_t hUpstreamProvider,
                    void (*trace)(const char *));

umf_memory_pool_handle_t
tracePoolCreate(umf_memory_pool_handle_t hUpstreamPool,
                umf_memory_provider_handle_t providerDesc,
                void (*trace)(const char *));

#ifdef __cplusplus
}
#endif

#endif /* UMF_TEST_HELPERS_H */
