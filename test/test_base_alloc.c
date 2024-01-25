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

#include "base_alloc.h"
#include "test_helpers.h"

#define NTHREADS 10
#define ITERATIONS 1000
#define ALLOCATION_SIZE 16

static void *start_routine(void *arg) {
    unsigned char *ptrs[ITERATIONS];
    umf_ba_pool_t *pool = (umf_ba_pool_t *)arg;

    long TID = syscall(SYS_gettid);

    for (int i = 0; i < ITERATIONS; i++) {
        ptrs[i] = umf_ba_alloc(pool);
        memset(ptrs[i], (i + TID) & 0xFF, ALLOCATION_SIZE);
    }

    for (int i = 0; i < ITERATIONS; i++) {
        for (int k = 0; k < ALLOCATION_SIZE; k++) {
            if (*(ptrs[i] + k) != ((i + TID) & 0xFF)) {
                fprintf(stderr,
                        "i = %i k = %i, *(ptrs[i] + k) = %i != ((i + TID) & "
                        "0xFF) = %li\n",
                        i, k, *(ptrs[i] + k), ((i + TID) & 0xFF));
            }
            UT_ASSERTeq(*(ptrs[i] + k), ((i + TID) & 0xFF));
        }
        umf_ba_free(pool, ptrs[i]);
    }

    return NULL;
}

int main() {
    pthread_t thread[NTHREADS];
    umf_ba_pool_t *pool = umf_ba_create(ALLOCATION_SIZE);

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

    umf_ba_destroy(pool);

    return 0;
}
