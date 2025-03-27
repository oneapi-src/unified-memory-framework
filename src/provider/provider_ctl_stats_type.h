/*
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#ifndef UMF_PROVIDER_CTL_STATS_TYPE_H
#define UMF_PROVIDER_CTL_STATS_TYPE_H 1

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ctl_stats_t {
    size_t allocated_memory;
    size_t peak_memory;
} ctl_stats_t;

#ifdef __cplusplus
}
#endif
#endif
