/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#ifndef UMF_BASE_ALLOC_GLOBAL_H
#define UMF_BASE_ALLOC_GLOBAL_H 1

#include "base_alloc.h"

#ifdef __cplusplus
extern "C" {
#endif

void *umf_ba_global_alloc(size_t size);
void umf_ba_global_free(void *ptr, size_t size);
void umf_ba_destroy_global(void);

#ifdef __cplusplus
}
#endif

#endif /* UMF_BASE_ALLOC_GLOBAL_H */
