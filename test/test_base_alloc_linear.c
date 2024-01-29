/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "base_alloc_linear.h"
#include "test_helpers.h"

#define NTHREADS 10
#define ITERATIONS 1000
#define MAX_ALLOCATION_SIZE 1024

static void *start_routine(void *arg) {
    struct buffer_t {
        unsigned char *ptr;
        size_t size;
    } buffer[ITERATIONS];
    umf_ba_linear_pool_t *pool = (umf_ba_linear_pool_t *)arg;

    long TID = syscall(SYS_gettid);

    for (int i = 0; i < ITERATIONS; i++) {
        buffer[i].size = (rand() * MAX_ALLOCATION_SIZE) / RAND_MAX;
        buffer[i].ptr = umf_ba_linear_alloc(pool, buffer[i].size);
        memset(buffer[i].ptr, (i + TID) & 0xFF, buffer[i].size);
    }

    for (int i = 0; i < ITERATIONS; i++) {
        for (int k = 0; k < buffer[i].size; k++) {
            if (*(buffer[i].ptr + k) != ((i + TID) & 0xFF)) {
                fprintf(
                    stderr,
                    "i = %i k = %i, *(buffer[i].ptr + k) = %i != ((i + TID) & "
                    "0xFF) = %li\n",
                    i, k, *(buffer[i].ptr + k), ((i + TID) & 0xFF));
            }
            UT_ASSERTeq(*(buffer[i].ptr + k), ((i + TID) & 0xFF));
        }
    }

    return NULL;
}

int main() {
    pthread_t thread[NTHREADS];
    umf_ba_linear_pool_t *pool = umf_ba_linear_create(MAX_ALLOCATION_SIZE);

    for (int i = 0; i < NTHREADS; i++) {
        int ret = pthread_create(&thread[i], NULL, start_routine, pool);
        if (ret) {
            fprintf(stderr, "pthread_create() failed!\n");
            UT_ASSERTeq(ret, 0);
        }
    }

    for (int i = 0; i < NTHREADS; i++) {
        void *retval;
        int ret = pthread_join(thread[i], &retval);
        if (ret) {
            fprintf(stderr, "pthread_join() failed!\n");
            UT_ASSERTeq(ret, 0);
        }
    }

    umf_ba_linear_destroy(pool);

    return 0;
}
