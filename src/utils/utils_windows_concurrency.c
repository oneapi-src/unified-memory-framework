/*
 *
 * Copyright (C) 2023-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "utils_concurrency.h"

size_t utils_mutex_get_size(void) { return sizeof(utils_mutex_t); }

utils_mutex_t *utils_mutex_init(void *ptr) {
    utils_mutex_t *mutex_internal = (utils_mutex_t *)ptr;
    InitializeCriticalSection(&mutex_internal->lock);
    return (utils_mutex_t *)mutex_internal;
}

void utils_mutex_destroy_not_free(utils_mutex_t *mutex) {
    utils_mutex_t *mutex_internal = (utils_mutex_t *)mutex;
    DeleteCriticalSection(&mutex_internal->lock);
}

int utils_mutex_lock(utils_mutex_t *mutex) {
    utils_mutex_t *mutex_internal = (utils_mutex_t *)mutex;
    EnterCriticalSection(&mutex_internal->lock);

    if (mutex_internal->lock.RecursionCount > 1) {
        LeaveCriticalSection(&mutex_internal->lock);
        /* deadlock detected */
        return -1;
    }
    return 0;
}

int utils_mutex_unlock(utils_mutex_t *mutex) {
    utils_mutex_t *mutex_internal = (utils_mutex_t *)mutex;
    LeaveCriticalSection(&mutex_internal->lock);
    return 0;
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
