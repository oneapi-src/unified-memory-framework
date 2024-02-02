/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#ifndef UMF_BASE_ALLOC_INTERNAL_H
#define UMF_BASE_ALLOC_INTERNAL_H 1

#include <stddef.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

void *baOsAlloc(size_t size);
void baOsFree(void *ptr, size_t size);
size_t baOsGetPageSize(void);

#ifdef __cplusplus
}
#endif

#endif /* UMF_BASE_ALLOC_INTERNAL_H */
