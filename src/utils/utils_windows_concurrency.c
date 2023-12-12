/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "utils_concurrency.h"

typedef struct {
    CRITICAL_SECTION lock;
} internal_os_mutex_t;

os_mutex_t *util_mutex_create(void) {
    internal_os_mutex_t *mutex_internal =
        (internal_os_mutex_t *)calloc(1, sizeof(internal_os_mutex_t));
    InitializeCriticalSection(&mutex_internal->lock);
    return (os_mutex_t *)mutex_internal;
}

void util_mutex_destroy(os_mutex_t *mutex) {
    internal_os_mutex_t *mutex_internal = (internal_os_mutex_t *)mutex;
    DeleteCriticalSection(&mutex_internal->lock);
}

int util_mutex_lock(os_mutex_t *mutex) {
    internal_os_mutex_t *mutex_internal = (internal_os_mutex_t *)mutex;
    EnterCriticalSection(&mutex_internal->lock);

    if (mutex_internal->lock.RecursionCount > 1) {
        LeaveCriticalSection(&mutex_internal->lock);
        /* deadlock detected */
        return -1;
    }
    return 0;
}

int util_mutex_unlock(os_mutex_t *mutex) {
    internal_os_mutex_t *mutex_internal = (internal_os_mutex_t *)mutex;
    LeaveCriticalSection(&mutex_internal->lock);
    return 0;
}
