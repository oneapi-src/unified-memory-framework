/*
 *
 * Copyright (C) 2023-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <pthread.h>
#include <stdlib.h>

#include "utils_concurrency.h"

size_t utils_mutex_get_size(void) { return sizeof(pthread_mutex_t); }

utils_mutex_t *utils_mutex_init(void *ptr) {
    pthread_mutex_t *mutex = (pthread_mutex_t *)ptr;
    int ret = pthread_mutex_init(mutex, NULL);
    return ret == 0 ? ((utils_mutex_t *)mutex) : NULL;
}

void utils_mutex_destroy_not_free(utils_mutex_t *m) {
    pthread_mutex_t *mutex = (pthread_mutex_t *)m;
    int ret = pthread_mutex_destroy(mutex);
    (void)ret; // TODO: add logging
}

int utils_mutex_lock(utils_mutex_t *m) {
    return pthread_mutex_lock((pthread_mutex_t *)m);
}

int utils_mutex_unlock(utils_mutex_t *m) {
    return pthread_mutex_unlock((pthread_mutex_t *)m);
}

void utils_init_once(UTIL_ONCE_FLAG *flag, void (*oneCb)(void)) {
    pthread_once(flag, oneCb);
}
