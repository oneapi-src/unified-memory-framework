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

umf_ba_pool_t *umf_ba_get_pool(size_t size);

#ifdef __cplusplus
}
#endif

#endif /* UMF_BASE_ALLOC_GLOBAL_H */
