/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "utils_concurrency.h"

size_t utils_mutex_get_size(void) { return sizeof(utils_mutex_t); }

utils_mutex_t *utils_mutex_init(utils_mutex_t *mutex) {
    InitializeCriticalSection(&mutex->lock);
    return mutex;
}

void utils_mutex_destroy_not_free(utils_mutex_t *mutex) {
    DeleteCriticalSection(&mutex->lock);
}

int utils_mutex_lock(utils_mutex_t *mutex) {
    EnterCriticalSection(&mutex->lock);

    if (mutex->lock.RecursionCount > 1) {
        LeaveCriticalSection(&mutex->lock);
        /* deadlock detected */
        return -1;
    }
    return 0;
}

int utils_mutex_unlock(utils_mutex_t *mutex) {
    LeaveCriticalSection(&mutex->lock);
    return 0;
}

utils_rwlock_t *utils_rwlock_init(utils_rwlock_t *rwlock) {
    InitializeSRWLock(&rwlock->lock);
    return 0; // never fails
}

void utils_rwlock_destroy_not_free(utils_rwlock_t *rwlock) {
    // there is no call to destroy SWR lock
    (void)rwlock;
}

int utils_read_lock(utils_rwlock_t *rwlock) {
    AcquireSRWLockShared(&rwlock->lock);
    return 0; // never fails
}

int utils_write_lock(utils_rwlock_t *rwlock) {
    AcquireSRWLockExclusive(&rwlock->lock);
    return 0; // never fails
}

int utils_read_unlock(utils_rwlock_t *rwlock) {
    ReleaseSRWLockShared(&rwlock->lock);
    return 0; // never fails
}

int utils_write_unlock(utils_rwlock_t *rwlock) {
    ReleaseSRWLockExclusive(&rwlock->lock);
    return 0; // never fails
}

static BOOL CALLBACK initOnceCb(PINIT_ONCE InitOnce, PVOID Parameter,
                                PVOID *lpContext) {
    (void)InitOnce;  // unused
    (void)lpContext; // unused

    void (*onceCb)(void) = (void (*)(void))(Parameter);
    onceCb();
    return TRUE;
}

void utils_init_once(UTIL_ONCE_FLAG *flag, void (*onceCb)(void)) {
    InitOnceExecuteOnce(flag, initOnceCb, (void *)onceCb, NULL);
}
