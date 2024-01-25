/*
 *
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_UTILS_CONCURRENCY_H
#define UMF_UTILS_CONCURRENCY_H 1

#include <stdio.h>
#if defined(_WIN32)
#include <windows.h>
#else
#include <stdatomic.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct os_mutex_t;

typedef struct os_mutex_t os_mutex_t;

os_mutex_t *util_mutex_create(void);
void util_mutex_destroy(os_mutex_t *mutex);
int util_mutex_lock(os_mutex_t *mutex);
int util_mutex_unlock(os_mutex_t *mutex);

#if defined(_WIN32)
static __inline unsigned char util_lssb_index(long long value) {
    unsigned long ret;
    _BitScanForward64(&ret, value);
    return (unsigned char)ret;
}
static __inline unsigned char util_mssb_index(long long value) {
    unsigned long ret;
    _BitScanReverse64(&ret, value);
    return (unsigned char)ret;
}

// There is no good way to do atomic_load on windows...
#define util_atomic_load_acquire(object, dest)                                 \
    do {                                                                       \
        *dest = InterlockedOr64Acquire((LONG64 volatile *)object, 0);          \
    } while (0)

#define util_atomic_store_release(object, desired)                             \
    InterlockedExchange64((LONG64 volatile *)object, (LONG64)desired)
#define util_atomic_increment(object)                                          \
    InterlockedIncrement64((LONG64 volatile *)object)
#else
#define util_lssb_index(x) ((unsigned char)__builtin_ctzll(x))
#define util_mssb_index(x) ((unsigned char)(63 - __builtin_clzll(x)))
#define util_atomic_load_acquire(object, dest)                                 \
    __atomic_load(object, dest, memory_order_acquire)
#define util_atomic_store_release(object, desired)                             \
    __atomic_store_n(object, desired, memory_order_release)
#define util_atomic_increment(object)                                          \
    __atomic_add_fetch(object, 1, __ATOMIC_ACQ_REL)
#endif

#ifdef __cplusplus
}
#endif

#endif /* UMF_UTILS_CONCURRENCY_H */
