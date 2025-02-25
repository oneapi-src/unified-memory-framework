/*
 *
 * Copyright (C) 2023-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_UTILS_CONCURRENCY_H
#define UMF_UTILS_CONCURRENCY_H 1

#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>

#include "utils_windows_intrin.h"

#pragma intrinsic(_BitScanForward64)
#else
#include <pthread.h>

#ifndef __cplusplus
#include <stdatomic.h>
#else /* __cplusplus */
#include <atomic>
#define _Atomic(X) std::atomic<X>
#endif /* __cplusplus */

#endif /* _WIN32 */

#include "utils_sanitizers.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct utils_mutex_t {
#ifdef _WIN32
    CRITICAL_SECTION lock;
#else
    pthread_mutex_t lock;
#endif
} utils_mutex_t;

size_t utils_mutex_get_size(void);
utils_mutex_t *utils_mutex_init(utils_mutex_t *ptr);
void utils_mutex_destroy_not_free(utils_mutex_t *m);
int utils_mutex_lock(utils_mutex_t *mutex);
int utils_mutex_unlock(utils_mutex_t *mutex);

typedef struct utils_rwlock_t {
#ifdef _WIN32
    // Slim Read/Wrtiter lock
    SRWLOCK lock;
#else
    pthread_rwlock_t rwlock;
#endif
} utils_rwlock_t;

utils_rwlock_t *utils_rwlock_init(utils_rwlock_t *ptr);
void utils_rwlock_destroy_not_free(utils_rwlock_t *rwlock);
int utils_read_lock(utils_rwlock_t *rwlock);
int utils_write_lock(utils_rwlock_t *rwlock);
int utils_read_unlock(utils_rwlock_t *rwlock);
int utils_write_unlock(utils_rwlock_t *rwlock);

#if defined(_WIN32)
#define UTIL_ONCE_FLAG INIT_ONCE
#define UTIL_ONCE_FLAG_INIT INIT_ONCE_STATIC_INIT
#else
#define UTIL_ONCE_FLAG pthread_once_t
#define UTIL_ONCE_FLAG_INIT PTHREAD_ONCE_INIT
#endif

void utils_init_once(UTIL_ONCE_FLAG *flag, void (*onceCb)(void));

#if defined(_WIN32)

static __inline unsigned char utils_lssb_index(long long value) {
    unsigned long ret;
    _BitScanForward64(&ret, value);
    return (unsigned char)ret;
}

static __inline unsigned char utils_mssb_index(long long value) {
    unsigned long ret;
    _BitScanReverse64(&ret, value);
    return (unsigned char)ret;
}

// There is no good way to do atomic_load on windows...
#define utils_atomic_load_acquire(object, dest)                                \
    do {                                                                       \
        *(LONG64 *)dest =                                                      \
            InterlockedOr64Acquire((LONG64 volatile *)object, 0);              \
    } while (0)

#define utils_atomic_store_release(object, desired)                            \
    InterlockedExchange64((LONG64 volatile *)object, (LONG64)desired)

#define utils_atomic_increment(object)                                         \
    InterlockedIncrement64((LONG64 volatile *)object)

#define utils_atomic_decrement(object)                                         \
    InterlockedDecrement64((LONG64 volatile *)object)

#define utils_fetch_and_add64(ptr, value)                                      \
    InterlockedExchangeAdd64((LONG64 *)(ptr), value)

// NOTE: windows version have different order of args
#define utils_compare_exchange(object, desired, expected)                      \
    InterlockedCompareExchange64((LONG64 volatile *)object, *expected, *desired)

#else // !defined(_WIN32)

#define utils_lssb_index(x) ((unsigned char)__builtin_ctzll(x))
#define utils_mssb_index(x) ((unsigned char)(63 - __builtin_clzll(x)))

#define utils_atomic_load_acquire(object, dest)                                \
    do {                                                                       \
        __atomic_load(object, dest, memory_order_acquire);                     \
        utils_annotate_acquire((void *)object);                                \
    } while (0)

#define utils_atomic_store_release(object, desired)                            \
    do {                                                                       \
        utils_annotate_release((void *)object);                                \
        __atomic_store_n(object, desired, memory_order_release);               \
    } while (0)

#define utils_atomic_increment(object)                                         \
    __atomic_add_fetch(object, 1, memory_order_acq_rel)

#define utils_atomic_decrement(object)                                         \
    __atomic_sub_fetch(object, 1, memory_order_acq_rel)

#define utils_fetch_and_add64(object, value)                                   \
    __atomic_fetch_add(object, value, memory_order_acq_rel)

#define utils_compare_exchange(object, expected, desired)                      \
    __atomic_compare_exchange(object, expected, desired, 0 /* strong */,       \
                              memory_order_acq_rel, memory_order_relaxed)

#endif // !defined(_WIN32)

#ifdef __cplusplus
}
#endif

#endif /* UMF_UTILS_CONCURRENCY_H */
