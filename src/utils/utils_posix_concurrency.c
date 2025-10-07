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
#include "utils_log.h"

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
    if (oneCb == NULL) {
        LOG_FATAL("utils_init_once: callback is NULL");
        return;
    }

    pthread_once(flag, oneCb);
}

int utils_rwlock_init(utils_rwlock_t *ptr) {
    pthread_rwlock_t *rwlock = (pthread_rwlock_t *)ptr;
    return pthread_rwlock_init(rwlock, NULL);
}

void utils_rwlock_destroy_not_free(utils_rwlock_t *ptr) {
    pthread_rwlock_t *rwlock = (pthread_rwlock_t *)ptr;
    if (pthread_rwlock_destroy(rwlock) != 0) {
        LOG_FATAL("pthread_rwlock_destroy failed");
        abort();
    }
}

void utils_read_lock(utils_rwlock_t *rwlock) {
    if (pthread_rwlock_rdlock((pthread_rwlock_t *)rwlock) != 0) {
        LOG_FATAL("pthread_rwlock_rdlock failed");
        abort();
    }
}

void utils_write_lock(utils_rwlock_t *rwlock) {
    if (pthread_rwlock_wrlock((pthread_rwlock_t *)rwlock) != 0) {
        LOG_FATAL("pthread_rwlock_wrlock failed");
        abort();
    }
}

void utils_read_unlock(utils_rwlock_t *rwlock) {
    if (pthread_rwlock_unlock((pthread_rwlock_t *)rwlock) != 0) {
        LOG_FATAL("pthread_rwlock_unlock failed");
        abort();
    }
}

void utils_write_unlock(utils_rwlock_t *rwlock) {
    if (pthread_rwlock_unlock((pthread_rwlock_t *)rwlock) != 0) {
        LOG_FATAL("pthread_rwlock_unlock failed");
        abort();
    }
}
