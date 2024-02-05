/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

/* A MT-safe fixed-size-pool base allocator */

#ifndef UMF_BASE_ALLOC_H
#define UMF_BASE_ALLOC_H 1

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct umf_ba_pool_t umf_ba_pool_t;

umf_ba_pool_t *umf_ba_create(size_t size);
void *umf_ba_alloc(umf_ba_pool_t *pool);
void umf_ba_free(umf_ba_pool_t *pool, void *ptr);
void umf_ba_destroy(umf_ba_pool_t *pool);

#ifdef __cplusplus
}
#endif

#endif /* UMF_BASE_ALLOC_H */
