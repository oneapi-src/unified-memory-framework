/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <assert.h>
#include <stdlib.h>

#include "base_alloc.h"
#include "base_alloc_global.h"
#include "utils_concurrency.h"

#define SIZE_BA_POOL_CHUNK 128

// global base allocator used by all providers and pools
static umf_ba_pool_t *BA_pool = NULL;
static UTIL_ONCE_FLAG ba_is_initialized = UTIL_ONCE_FLAG_INIT;

static void umf_ba_create_global(void) {
    assert(BA_pool == NULL);
    BA_pool = umf_ba_create(SIZE_BA_POOL_CHUNK);
    assert(BA_pool);
#if defined(_WIN32) && !defined(UMF_SHARED_LIBRARY)
    atexit(umf_ba_destroy_global);
#endif
}

void umf_ba_destroy_global(void) {
    if (BA_pool) {
        umf_ba_pool_t *pool = BA_pool;
        BA_pool = NULL;
        umf_ba_destroy(pool);
    }
}

umf_ba_pool_t *umf_ba_get_pool(size_t size) {
    util_init_once(&ba_is_initialized, umf_ba_create_global);

    if (!BA_pool) {
        return NULL;
    }

    // TODO: a specific class-size base allocator can be returned here
    assert(size <= SIZE_BA_POOL_CHUNK);

    if (size > SIZE_BA_POOL_CHUNK) {
        return NULL;
    }

    return BA_pool;
}
