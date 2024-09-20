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
#include <string.h>

#include "base_alloc.h"
#include "base_alloc_global.h"
#include "base_alloc_internal.h"
#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_log.h"
#include "utils_math.h"
#include "utils_sanitizers.h"

// global base allocator used by all providers and pools
static UTIL_ONCE_FLAG ba_is_initialized = UTIL_ONCE_FLAG_INIT;

#define ALLOC_METADATA_SIZE (sizeof(size_t))

// allocation classes need to be consecutive powers of 2
#define ALLOCATION_CLASSES                                                     \
    { 16, 32, 64, 128, 256 }
#define NUM_ALLOCATION_CLASSES 5

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

    // portable version of "ba_is_initialized = UTIL_ONCE_FLAG_INIT;"
    static UTIL_ONCE_FLAG is_initialized = UTIL_ONCE_FLAG_INIT;
    memcpy(&ba_is_initialized, &is_initialized, sizeof(ba_is_initialized));
}

static void umf_ba_create_global(void) {
    for (int i = 0; i < NUM_ALLOCATION_CLASSES; i++) {
        // allocation classes need to be powers of 2
        assert(0 == (BASE_ALLOC.ac_sizes[i] & (BASE_ALLOC.ac_sizes[i] - 1)));
        BASE_ALLOC.ac[i] = umf_ba_create(BASE_ALLOC.ac_sizes[i]);
        if (!BASE_ALLOC.ac[i]) {
            LOG_ERR("base_alloc: Cannot create base alloc allocation "
                    "class for size: %zu\n. Each allocation will fallback to "
                    "allocating memory from the OS.",
                    BASE_ALLOC.ac_sizes[i]);
        }
    }

    size_t smallestSize = BASE_ALLOC.ac_sizes[0];
    BASE_ALLOC.smallest_ac_size_log2 = log2Utils(smallestSize);
}

// returns index of the allocation class for a given size
static int size_to_idx(size_t size) {
    if (size <= BASE_ALLOC.ac_sizes[0]) {
        return 0;
    }

    int isPowerOf2 = (0 == (size & (size - 1)));
    int index =
        (int)(log2Utils(size) + !isPowerOf2 - BASE_ALLOC.smallest_ac_size_log2);

    assert(index >= 0);
    return index;
}

// stores metadata just before 'ptr' and returns beginning of usable
// space to the user. metadata consists of 'size' that is the allocation
// size and 'offset' that specifies how far is the returned ptr from
// the origin ptr (used for aligned alloc)
static void *add_metadata_and_align(void *ptr, size_t size, size_t alignment) {
    assert(size < (1ULL << 32));
    assert(alignment < (1ULL << 32));
    assert(ptr);

    void *user_ptr;
    if (alignment <= ALLOC_METADATA_SIZE) {
        user_ptr = (void *)((uintptr_t)ptr + ALLOC_METADATA_SIZE);
    } else {
        user_ptr =
            (void *)ALIGN_UP((uintptr_t)ptr + ALLOC_METADATA_SIZE, alignment);
    }

    size_t ptr_offset_from_original = (uintptr_t)user_ptr - (uintptr_t)ptr;
    assert(ptr_offset_from_original < (1ULL << 32));

    size_t *metadata_loc = (size_t *)((char *)user_ptr - ALLOC_METADATA_SIZE);

    // mark entire allocation as undefined memory so that we can store metadata
    utils_annotate_memory_undefined(ptr, size);

    *metadata_loc = size | (ptr_offset_from_original << 32);

    // mark the metadata part as inaccessible
    utils_annotate_memory_inaccessible(ptr, ptr_offset_from_original);

    return user_ptr;
}

// return original ptr (the one that has been passed to add_metadata_and_align)
// along with total allocation size (needed to find proper alloc class
// in free) and usable size
static void *get_original_alloc(void *user_ptr, size_t *total_size,
                                size_t *usable_size) {
    assert(user_ptr);

    size_t *metadata_loc = (size_t *)((char *)user_ptr - ALLOC_METADATA_SIZE);

    // mark the metadata as defined to read the size and offset
    utils_annotate_memory_defined(metadata_loc, ALLOC_METADATA_SIZE);

    size_t stored_size = *metadata_loc & ((1ULL << 32) - 1);
    size_t ptr_offset_from_original = *metadata_loc >> 32;

    // restore the original access mode
    utils_annotate_memory_inaccessible(metadata_loc, ALLOC_METADATA_SIZE);

    void *original_ptr =
        (void *)((uintptr_t)user_ptr - ptr_offset_from_original);

    if (total_size) {
        *total_size = stored_size;
    }

    if (usable_size) {
        *usable_size = stored_size - ptr_offset_from_original;
    }

    return original_ptr;
}

void *umf_ba_global_aligned_alloc(size_t size, size_t alignment) {
    utils_init_once(&ba_is_initialized, umf_ba_create_global);

    if (size == 0) {
        return NULL;
    }

    // for metadata
    size += ALLOC_METADATA_SIZE;

    if (alignment > ALLOC_METADATA_SIZE) {
        size += alignment;
    }

    int ac_index = size_to_idx(size);
    if (ac_index >= NUM_ALLOCATION_CLASSES) {
        return add_metadata_and_align(ba_os_alloc(size), size, alignment);
    }

    if (!BASE_ALLOC.ac[ac_index]) {
        // if creating ac failed, fall back to os allocation
        LOG_WARN("base_alloc: allocation class not created. Falling "
                 "back to OS memory allocation.");
        return add_metadata_and_align(ba_os_alloc(size), size, alignment);
    }

    return add_metadata_and_align(umf_ba_alloc(BASE_ALLOC.ac[ac_index]), size,
                                  alignment);
}

void *umf_ba_global_alloc(size_t size) {
    return umf_ba_global_aligned_alloc(size, ALLOC_METADATA_SIZE);
}

void umf_ba_global_free(void *ptr) {
    if (!ptr) {
        return;
    }

    size_t total_size;
    ptr = get_original_alloc(ptr, &total_size, NULL);

    int ac_index = size_to_idx(total_size);
    if (ac_index >= NUM_ALLOCATION_CLASSES) {
        ba_os_free(ptr, total_size);
        return;
    }

    if (!BASE_ALLOC.ac[ac_index]) {
        // if creating ac failed, memory must have been allocated by os
        ba_os_free(ptr, total_size);
        return;
    }

    // base_alloc expects the allocation to be undefined memory
    utils_annotate_memory_undefined(ptr, total_size);
    umf_ba_free(BASE_ALLOC.ac[ac_index], ptr);
}

size_t umf_ba_global_malloc_usable_size(void *ptr) {
    if (!ptr) {
        return 0;
    }

    size_t usable_size;
    get_original_alloc(ptr, NULL, &usable_size);

    return usable_size;
}
