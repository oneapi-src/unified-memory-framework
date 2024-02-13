/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "utils_concurrency.h"

size_t util_mutex_get_size(void) { return sizeof(os_mutex_t); }

os_mutex_t *util_mutex_init(void *ptr) {
    os_mutex_t *mutex_internal = (os_mutex_t *)ptr;
    InitializeCriticalSection(&mutex_internal->lock);
    return (os_mutex_t *)mutex_internal;
}

void util_mutex_destroy_not_free(os_mutex_t *mutex) {
    os_mutex_t *mutex_internal = (os_mutex_t *)mutex;
    DeleteCriticalSection(&mutex_internal->lock);
}

int util_mutex_lock(os_mutex_t *mutex) {
    os_mutex_t *mutex_internal = (os_mutex_t *)mutex;
    EnterCriticalSection(&mutex_internal->lock);

    if (mutex_internal->lock.RecursionCount > 1) {
        LeaveCriticalSection(&mutex_internal->lock);
        /* deadlock detected */
        return -1;
    }
    return 0;
}

int util_mutex_unlock(os_mutex_t *mutex) {
    os_mutex_t *mutex_internal = (os_mutex_t *)mutex;
    LeaveCriticalSection(&mutex_internal->lock);
    return 0;
}

static BOOL CALLBACK initOnceCb(PINIT_ONCE InitOnce, PVOID Parameter,
                                PVOID *lpContext) {
    void (*onceCb)(void) = (void (*)(void))(Parameter);
    onceCb();
    return TRUE;
}

void util_init_once(UTIL_ONCE_FLAG *flag, void (*onceCb)(void)) {
    InitOnceExecuteOnce(flag, initOnceCb, (void *)onceCb, NULL);
}
