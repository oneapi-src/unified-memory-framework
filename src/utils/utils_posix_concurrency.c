/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <pthread.h>
#include <stdlib.h>

#include "utils_concurrency.h"
#include "utils_log.h"

//typedef union pthread_rwlock_t pthread_rwlock_t;

size_t utils_mutex_get_size(void) { return sizeof(pthread_mutex_t); }

utils_mutex_t *utils_mutex_init(utils_mutex_t *ptr) {
    pthread_mutex_t *mutex = (pthread_mutex_t *)ptr;
    int ret = pthread_mutex_init(mutex, NULL);
    return ret == 0 ? ((utils_mutex_t *)mutex) : NULL;
}

void utils_mutex_destroy_not_free(utils_mutex_t *m) {
    pthread_mutex_t *mutex = (pthread_mutex_t *)m;
    int ret = pthread_mutex_destroy(mutex);
    if (ret) {
        LOG_ERR("pthread_mutex_destroy failed");
    }
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

utils_rwlock_t *utils_rwlock_init(utils_rwlock_t *ptr) {
    pthread_rwlock_t *rwlock = (pthread_rwlock_t *)ptr;
    int ret = pthread_rwlock_init(rwlock, NULL);
    return ret == 0 ? ((utils_rwlock_t *)rwlock) : NULL;
}

void utils_rwlock_destroy_not_free(utils_rwlock_t *ptr) {
    pthread_rwlock_t *rwlock = (pthread_rwlock_t *)ptr;
    int ret = pthread_rwlock_destroy(rwlock);
    if (ret) {
        LOG_ERR("pthread_rwlock_destroy failed");
    }
}

int utils_read_lock(utils_rwlock_t *rwlock) {
    return pthread_rwlock_rdlock((pthread_rwlock_t *)rwlock);
}

int utils_write_lock(utils_rwlock_t *rwlock) {
    return pthread_rwlock_wrlock((pthread_rwlock_t *)rwlock);
}

int utils_read_unlock(utils_rwlock_t *rwlock) {
    return pthread_rwlock_unlock((pthread_rwlock_t *)rwlock);
}

int utils_write_unlock(utils_rwlock_t *rwlock) {
    return pthread_rwlock_unlock((pthread_rwlock_t *)rwlock);
}
