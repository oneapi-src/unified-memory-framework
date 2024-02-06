/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

/* A MT-safe base allocator */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "base_alloc.h"
#include "base_alloc_global.h"
#include "base_alloc_internal.h"
#include "utils_concurrency.h"
#include "utils_math.h"

// global base allocator used by all providers and pools
static UTIL_ONCE_FLAG ba_is_initialized = UTIL_ONCE_FLAG_INIT;

// allocation classes need to be powers of 2
#define ALLOCATION_CLASSES                                                     \
    { 16, 32, 64, 128 }
#define NUM_ALLOCATION_CLASSES 4

struct base_alloc_t {
    size_t ac_sizes[NUM_ALLOCATION_CLASSES];
    umf_ba_pool_t *ac[NUM_ALLOCATION_CLASSES];
    size_t smallest_ac_size_log2;
};

static struct base_alloc_t BASE_ALLOC = {.ac_sizes = ALLOCATION_CLASSES};

void umf_ba_destroy_global(void) {
    for (int i = 0; i < NUM_ALLOCATION_CLASSES; i++) {
        if (BASE_ALLOC.ac[i]) {
            umf_ba_destroy(BASE_ALLOC.ac[i]);
            BASE_ALLOC.ac[i] = NULL;
        }
    }
}

static void umf_ba_create_global(void) {
    for (int i = 0; i < NUM_ALLOCATION_CLASSES; i++) {
        // allocation classes need to be powers of 2
        assert(0 == (BASE_ALLOC.ac_sizes[i] & (BASE_ALLOC.ac_sizes[i] - 1)));
        BASE_ALLOC.ac[i] = umf_ba_create(BASE_ALLOC.ac_sizes[i]);
        if (!BASE_ALLOC.ac[i]) {
            fprintf(stderr,
                    "base_alloc: Error. Cannot create base alloc allocation "
                    "class for size: %zu\n. Each allocation will fallback to "
                    "allocating memory from the OS.",
                    BASE_ALLOC.ac_sizes[i]);
        }
    }

    size_t smallestSize = BASE_ALLOC.ac_sizes[0];
    BASE_ALLOC.smallest_ac_size_log2 = log2Utils(smallestSize);

#if defined(_WIN32) && !defined(UMF_SHARED_LIBRARY)
    atexit(umf_ba_destroy_global);
#endif
}

// returns index of the allocation class for a given size
static int size_to_idx(size_t size) {
    assert(size <= BASE_ALLOC.ac_sizes[NUM_ALLOCATION_CLASSES - 1]);

    if (size <= BASE_ALLOC.ac_sizes[0]) {
        return 0;
    }

    int isPowerOf2 = (0 == (size & (size - 1)));
    int index =
        (int)(log2Utils(size) + !isPowerOf2 - BASE_ALLOC.smallest_ac_size_log2);

    assert(index >= 0);
    assert(index < NUM_ALLOCATION_CLASSES);

    return index;
}

void *umf_ba_global_alloc(size_t size) {
    util_init_once(&ba_is_initialized, umf_ba_create_global);

    if (size > BASE_ALLOC.ac_sizes[NUM_ALLOCATION_CLASSES - 1]) {
        fprintf(stderr,
                "base_alloc: allocation size larger than the biggest "
                "allocation class. Falling back to OS memory allocation.\n");
        return ba_os_alloc(size);
    }

    int ac_index = size_to_idx(size);
    if (!BASE_ALLOC.ac[ac_index]) {
        // if creating ac failed, fall back to os allocation
        fprintf(stderr, "base_alloc: allocation class not created. Falling "
                        "back to OS memory allocation.\n");
        return ba_os_alloc(size);
    }

    return umf_ba_alloc(BASE_ALLOC.ac[ac_index]);
}

void umf_ba_global_free(void *ptr, size_t size) {
    if (size > BASE_ALLOC.ac_sizes[NUM_ALLOCATION_CLASSES - 1]) {
        ba_os_free(ptr, size);
        return;
    }

    int ac_index = size_to_idx(size);
    if (!BASE_ALLOC.ac[ac_index]) {
        // if creating ac failed, memory must have been allocated by os
        ba_os_free(ptr, size);
        return;
    }

    umf_ba_free(BASE_ALLOC.ac[ac_index], ptr);
}
