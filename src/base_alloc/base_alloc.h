/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

/* A MT-safe fixed-size-allocation-class base allocator */

#ifndef UMF_BASE_ALLOC_AC_H
#define UMF_BASE_ALLOC_AC_H 1

#include <stddef.h>

typedef struct umf_ba_alloc_class_t umf_ba_alloc_class_t;

umf_ba_alloc_class_t *umfBaAllocClassCreate(size_t size);
void *umfBaAllocClassAllocate(umf_ba_alloc_class_t *ac);
void umfBaAllocClassFree(umf_ba_alloc_class_t *ac, void *ptr);
void umfBaAllocClassDestroy(umf_ba_alloc_class_t *ac);

#endif /* UMF_BASE_ALLOC_AC_H */
