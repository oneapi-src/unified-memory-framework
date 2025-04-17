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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>

#include "utils_windows_intrin.h"

#pragma intrinsic(_BitScanForward64)
#else /* !_WIN32 */
#include <pthread.h>

#ifndef __cplusplus
#include <stdatomic.h>
#else /* __cplusplus */
#include <atomic>
#define _Atomic(X) std::atomic<X>

// TODO remove cpp code from this file
using std::memory_order_acq_rel;
using std::memory_order_acquire;
using std::memory_order_relaxed;
using std::memory_order_release;

#endif /* __cplusplus */

#endif /* !_WIN32 */

#include "utils_assert.h"
#include "utils_common.h"
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

// There is no good way to do atomic_load on windows...
static inline void utils_atomic_load_acquire_u64(uint64_t *ptr, uint64_t *out) {
    // NOTE: Windows cl complains about direct accessing 'ptr' which is next
    // accessed using Interlocked* functions (warning 28112 - disabled)
    ASSERT_IS_ALIGNED((uintptr_t)ptr, 8);

    // On Windows, there is no equivalent to __atomic_load, so we use cmpxchg
    // with 0, 0 here. This will always return the value under the pointer
    // without writing anything.
    LONG64 ret = InterlockedCompareExchange64((LONG64 volatile *)ptr, 0, 0);
    *out = *(uint64_t *)&ret;
}

static inline void utils_atomic_load_acquire_ptr(void **ptr, void **out) {
    ASSERT_IS_ALIGNED((uintptr_t)ptr, 8);
    uintptr_t ret = (uintptr_t)InterlockedCompareExchangePointer(ptr, 0, 0);
    *(uintptr_t *)out = ret;
}

static inline void utils_atomic_store_release_u64(uint64_t *ptr, uint64_t val) {
    ASSERT_IS_ALIGNED((uintptr_t)ptr, 8);
    InterlockedExchange64((LONG64 volatile *)ptr, val);
}

static inline void utils_atomic_store_release_ptr(void **ptr, void *val) {
    ASSERT_IS_ALIGNED((uintptr_t)ptr, 8);
    InterlockedExchangePointer(ptr, val);
}

static inline uint64_t utils_atomic_increment_u64(uint64_t *ptr) {
    ASSERT_IS_ALIGNED((uintptr_t)ptr, 8);
    // return incremented value
    return InterlockedIncrement64((LONG64 volatile *)ptr);
}

static inline uint64_t utils_atomic_decrement_u64(uint64_t *ptr) {
    ASSERT_IS_ALIGNED((uintptr_t)ptr, 8);
    // return decremented value
    return InterlockedDecrement64((LONG64 volatile *)ptr);
}

static inline uint64_t utils_atomic_and_u64(uint64_t *ptr, uint64_t val) {
    ASSERT_IS_ALIGNED((uintptr_t)ptr, 8);
    // return the value that had previously been in *ptr
    return InterlockedAnd64((LONG64 volatile *)(ptr), val);
}

static inline uint64_t utils_fetch_and_add_u64(uint64_t *ptr, uint64_t val) {
    ASSERT_IS_ALIGNED((uintptr_t)ptr, 8);
    // return the value that had previously been in *ptr
    return InterlockedExchangeAdd64((LONG64 volatile *)(ptr), val);
}

static inline uint64_t utils_fetch_and_sub_u64(uint64_t *ptr, uint64_t val) {
    ASSERT_IS_ALIGNED((uintptr_t)ptr, 8);
    // return the value that had previously been in *ptr
    // NOTE: on Windows there is no *Sub* version of InterlockedExchange
    return InterlockedExchangeAdd64((LONG64 volatile *)(ptr), -(LONG64)val);
}

static inline bool utils_compare_exchange_u64(uint64_t *ptr, uint64_t *expected,
                                              uint64_t *desired) {
    ASSERT_IS_ALIGNED((uintptr_t)ptr, 8);
    LONG64 out = InterlockedCompareExchange64(
        (LONG64 volatile *)ptr, *(LONG64 *)desired, *(LONG64 *)expected);
    if (out == *(LONG64 *)expected) {
        return true;
    }

    // else
    *expected = out;
    return false;
}

#else // !defined(_WIN32)

static inline void utils_atomic_load_acquire_u64(uint64_t *ptr, uint64_t *out) {
    ASSERT_IS_ALIGNED((uintptr_t)ptr, 8);
    ASSERT_IS_ALIGNED((uintptr_t)out, 8);
    __atomic_load(ptr, out, memory_order_acquire);
    utils_annotate_acquire(ptr);
}

static inline void utils_atomic_load_acquire_ptr(void **ptr, void **out) {
    ASSERT_IS_ALIGNED((uintptr_t)ptr, 8);
    ASSERT_IS_ALIGNED((uintptr_t)out, 8);
    __atomic_load((uintptr_t *)ptr, (uintptr_t *)out, memory_order_acquire);
    utils_annotate_acquire(ptr);
}

static inline void utils_atomic_store_release_u64(uint64_t *ptr, uint64_t val) {
    ASSERT_IS_ALIGNED((uintptr_t)ptr, 8);
    utils_annotate_release(ptr);
    __atomic_store_n(ptr, val, memory_order_release);
}

static inline void utils_atomic_store_release_ptr(void **ptr, void *val) {
    ASSERT_IS_ALIGNED((uintptr_t)ptr, 8);
    utils_annotate_release(ptr);
    __atomic_store_n((uintptr_t *)ptr, (uintptr_t)val, memory_order_release);
}

static inline uint64_t utils_atomic_increment_u64(uint64_t *val) {
    ASSERT_IS_ALIGNED((uintptr_t)val, 8);
    // return incremented value
    return __atomic_add_fetch(val, 1, memory_order_acq_rel);
}

static inline uint64_t utils_atomic_decrement_u64(uint64_t *val) {
    ASSERT_IS_ALIGNED((uintptr_t)val, 8);
    // return decremented value
    return __atomic_sub_fetch(val, 1, memory_order_acq_rel);
}

static inline uint64_t utils_atomic_and_u64(uint64_t *ptr, uint64_t val) {
    ASSERT_IS_ALIGNED((uintptr_t)ptr, 8);
    // return the value that had previously been in *ptr
    return __atomic_fetch_and(ptr, val, memory_order_acq_rel);
}

static inline uint64_t utils_fetch_and_add_u64(uint64_t *ptr, uint64_t val) {
    ASSERT_IS_ALIGNED((uintptr_t)ptr, 8);
    // return the value that had previously been in *ptr
    return __atomic_fetch_add(ptr, val, memory_order_acq_rel);
}

static inline uint64_t utils_fetch_and_sub_u64(uint64_t *ptr, uint64_t val) {
    // return the value that had previously been in *ptr
    ASSERT_IS_ALIGNED((uintptr_t)ptr, 8);
    return __atomic_fetch_sub(ptr, val, memory_order_acq_rel);
}

static inline bool utils_compare_exchange_u64(uint64_t *ptr, uint64_t *expected,
                                              uint64_t *desired) {
    ASSERT_IS_ALIGNED((uintptr_t)ptr, 8);
    return __atomic_compare_exchange(ptr, expected, desired, 0 /* strong */,
                                     memory_order_acq_rel,
                                     memory_order_relaxed);
}

#endif // !defined(_WIN32)

static inline void utils_atomic_load_acquire_size_t(size_t *ptr, size_t *out) {
    COMPILE_ERROR_ON(sizeof(size_t) != sizeof(uint64_t));
    utils_atomic_load_acquire_u64((uint64_t *)ptr, (uint64_t *)out);
}

static inline void utils_atomic_store_release_size_t(size_t *ptr, size_t val) {
    COMPILE_ERROR_ON(sizeof(size_t) != sizeof(uint64_t));
    utils_atomic_store_release_u64((uint64_t *)ptr, (uint64_t)val);
}

static inline size_t utils_fetch_and_add_size_t(size_t *ptr, size_t val) {
    COMPILE_ERROR_ON(sizeof(size_t) != sizeof(uint64_t));
    return utils_fetch_and_add_u64((uint64_t *)ptr, (uint64_t)val);
}

static inline size_t utils_fetch_and_sub_size_t(size_t *ptr, size_t val) {
    COMPILE_ERROR_ON(sizeof(size_t) != sizeof(uint64_t));
    return utils_fetch_and_sub_u64((uint64_t *)ptr, (uint64_t)val);
}

static inline bool utils_compare_exchange_size_t(size_t *ptr, size_t *expected,
                                                 size_t *desired) {
    COMPILE_ERROR_ON(sizeof(size_t) != sizeof(uint64_t));
    return utils_compare_exchange_u64((uint64_t *)ptr, (uint64_t *)expected,
                                      (uint64_t *)desired);
}

#ifdef __cplusplus
}
#endif

#endif /* UMF_UTILS_CONCURRENCY_H */
