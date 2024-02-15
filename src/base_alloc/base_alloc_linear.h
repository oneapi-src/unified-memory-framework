/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

/*
 * A MT-safe linear base allocator.
 * Useful for a few, small and different size allocations
 * for a most/whole life-time of an application
 * (since free() is not available).
 */

#ifndef UMF_BASE_ALLOC_LINEAR_H
#define UMF_BASE_ALLOC_LINEAR_H 1

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct umf_ba_linear_pool umf_ba_linear_pool_t;

umf_ba_linear_pool_t *umf_ba_linear_create(size_t pool_size);
void *umf_ba_linear_alloc(umf_ba_linear_pool_t *pool, size_t size);
void umf_ba_linear_destroy(umf_ba_linear_pool_t *pool);
size_t umf_ba_linear_pool_contains_pointer(umf_ba_linear_pool_t *pool,
                                           void *ptr);

#ifdef __cplusplus
}
#endif

#endif /* UMF_BASE_ALLOC_LINEAR_H */
