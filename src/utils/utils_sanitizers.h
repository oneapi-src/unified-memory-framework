/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_UTILS_SANITIZERS_H
#define UMF_UTILS_SANITIZERS_H 1

#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#ifndef __SANITIZE_THREAD__
#define __SANITIZE_THREAD__ 1
#endif
#endif
#if __has_feature(address_sanitizer)
#ifndef __SANITIZE_ADDRESS__
#define __SANITIZE_ADDRESS__ 1
#endif
#endif
#endif

#if UMF_VG_ENABLED
#undef UMF_VG_MEMCHECK_ENABLED
#undef UMF_VG_HELGRIND_ENABLED
#undef UMF_VG_DRD_ENABLED

#define UMF_VG_MEMCHECK_ENABLED 1
#define UMF_VG_HELGRIND_ENABLED 1
#define UMF_VG_DRD_ENABLED 1
#endif

#if UMF_VG_MEMCHECK_ENABLED || UMF_VG_HELGRIND_ENABLED || UMF_VG_DRD_ENABLED
#define UMF_ANY_VG_TOOL_ENABLED 1
#endif

#if UMF_ANY_VG_TOOL_ENABLED
#include <valgrind.h>
#endif

#if UMF_VG_MEMCHECK_ENABLED
#include <memcheck.h>
#endif

#if UMF_VG_HELGRIND_ENABLED
#include <helgrind.h>
#endif

#if UMF_VG_DRD_ENABLED
#include <drd.h>
#endif

#if __SANITIZE_THREAD__
#include <sanitizer/tsan_interface.h>
#endif

#if __SANITIZE_ADDRESS__
#include <sanitizer/asan_interface.h>
#endif

#if UMF_VG_MEMCHECK_ENABLED
#define VALGRIND_DO_MALLOCLIKE_BLOCK VALGRIND_MALLOCLIKE_BLOCK
#define VALGRIND_DO_FREELIKE_BLOCK VALGRIND_FREELIKE_BLOCK
#define VALGRIND_DO_CREATE_MEMPOOL VALGRIND_CREATE_MEMPOOL
#define VALGRIND_DO_DESTROY_MEMPOOL VALGRIND_DESTROY_MEMPOOL
#define VALGRIND_DO_MEMPOOL_ALLOC VALGRIND_MEMPOOL_ALLOC
#define VALGRIND_DO_MEMPOOL_FREE VALGRIND_MEMPOOL_FREE
#else
#define VALGRIND_DO_MALLOCLIKE_BLOCK(ptr, size, rzB, is_zeroed)                \
    do {                                                                       \
        (void)(ptr);                                                           \
        (void)(size);                                                          \
        (void)(rzB);                                                           \
        (void)(is_zeroed);                                                     \
    } while (0)

#define VALGRIND_DO_FREELIKE_BLOCK(ptr, rzB)                                   \
    do {                                                                       \
        (void)(ptr);                                                           \
        (void)(rzB);                                                           \
    } while (0)

#define VALGRIND_DO_CREATE_MEMPOOL(pool, rzB, is_zeroed)                       \
    do {                                                                       \
        (void)(pool);                                                          \
        (void)(rzB);                                                           \
        (void)(is_zeroed);                                                     \
    } while (0)

#define VALGRIND_DO_DESTROY_MEMPOOL(pool)                                      \
    do {                                                                       \
        (void)(pool);                                                          \
    } while (0)

#define VALGRIND_DO_MEMPOOL_ALLOC(pool, ptr, size)                             \
    do {                                                                       \
        (void)(pool);                                                          \
        (void)(ptr);                                                           \
        (void)(size);                                                          \
    } while (0)

#define VALGRIND_DO_MEMPOOL_FREE(pool, ptr)                                    \
    do {                                                                       \
        (void)(pool);                                                          \
        (void)(ptr);                                                           \
    } while (0)
#endif

#ifdef __cplusplus
extern "C" {
#endif

static inline void utils_annotate_acquire(void *ptr) {
#if __SANITIZE_THREAD__
    __tsan_acquire(ptr);
#elif UMF_VG_HELGRIND_ENABLED || UMF_VG_DRD_ENABLED
    ANNOTATE_HAPPENS_AFTER(ptr);
#else
    (void)ptr;
#endif
}

static inline void utils_annotate_release(void *ptr) {
#if __SANITIZE_THREAD__
    __tsan_release(ptr);
#elif UMF_VG_HELGRIND_ENABLED || UMF_VG_DRD_ENABLED
    ANNOTATE_HAPPENS_BEFORE(ptr);
#else
    (void)ptr;
#endif
}

// mark memory as accessible, defined
static inline void utils_annotate_memory_defined(void *ptr, size_t size) {
#ifdef __SANITIZE_ADDRESS__
    __asan_unpoison_memory_region(ptr, size);
#elif UMF_VG_MEMCHECK_ENABLED
    VALGRIND_MAKE_MEM_DEFINED(ptr, size);
#else
    (void)ptr;
    (void)size;
#endif
}

// mark memory as accessible, undefined
static inline void utils_annotate_memory_undefined(void *ptr, size_t size) {
#ifdef __SANITIZE_ADDRESS__
    __asan_unpoison_memory_region(ptr, size);
#elif UMF_VG_MEMCHECK_ENABLED
    VALGRIND_MAKE_MEM_UNDEFINED(ptr, size);
#else
    (void)ptr;
    (void)size;
#endif
}

static inline void utils_annotate_memory_inaccessible(void *ptr, size_t size) {
#ifdef __SANITIZE_ADDRESS__
    __asan_poison_memory_region(ptr, size);
#elif UMF_VG_MEMCHECK_ENABLED
    VALGRIND_MAKE_MEM_NOACCESS(ptr, size);
#else
    (void)ptr;
    (void)size;
#endif
}

#ifdef __cplusplus
}
#endif

#endif /* UMF_UTILS_SANITIZERS_H */
