/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <assert.h>

#include "base_alloc.h"

#define SIZE_BA_POOL_CHUNK 128

// global base allocator used by all providers and pools
static umf_ba_pool_t *BA_pool = NULL;

int umf_ba_create_global(void) {
    assert(BA_pool == NULL);

    BA_pool = umf_ba_create(SIZE_BA_POOL_CHUNK);
    if (!BA_pool) {
        return -1;
    }

    return 0;
}

void umf_ba_destroy_global(void) {
    assert(BA_pool);
    umf_ba_destroy(BA_pool);
    BA_pool = NULL;
}

umf_ba_pool_t *umf_ba_get_pool(size_t size) {
    // TODO: a specific class-size base allocator can be returned here
    assert(BA_pool);
    assert(size <= SIZE_BA_POOL_CHUNK);

    if (size > SIZE_BA_POOL_CHUNK) {
        return NULL;
    }

    return BA_pool;
}
