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

size_t util_mutex_get_size(void) { return sizeof(pthread_mutex_t); }

os_mutex_t *util_mutex_init(void *ptr) {
    pthread_mutex_t *mutex = (pthread_mutex_t *)ptr;
    int ret = pthread_mutex_init(mutex, NULL);
    return ret == 0 ? ((os_mutex_t *)mutex) : NULL;
}

os_mutex_t *util_mutex_create(void) {
    return util_mutex_init(malloc(util_mutex_get_size()));
}

void util_mutex_destroy_not_free(os_mutex_t *m) {
    pthread_mutex_t *mutex = (pthread_mutex_t *)m;
    int ret = pthread_mutex_destroy(mutex);
    (void)ret; // TODO: add logging
}

void util_mutex_destroy(os_mutex_t *m) {
    util_mutex_destroy_not_free(m);
    free(m);
}

int util_mutex_lock(os_mutex_t *m) {
    return pthread_mutex_lock((pthread_mutex_t *)m);
}

int util_mutex_unlock(os_mutex_t *m) {
    return pthread_mutex_unlock((pthread_mutex_t *)m);
}
