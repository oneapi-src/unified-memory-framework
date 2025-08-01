/*
 *
 * Copyright (C) 2023-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_MEMORY_POOL_INTERNAL_H
#define UMF_MEMORY_POOL_INTERNAL_H 1

#include <umf/base.h>
#include <umf/memory_pool.h>
#include <umf/memory_pool_ops.h>
#include <umf/memory_provider.h>

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "base_alloc.h"
#include "ctl/ctl_internal.h"
#include "utils_concurrency.h"

typedef struct umf_pool_stats {
    size_t alloc_count;
} umf_pool_stats_t;

typedef struct umf_memory_pool_t {
    void *pool_priv;
    umf_pool_create_flags_t flags;

    // Memory provider used by the pool.
    umf_memory_provider_handle_t provider;

    utils_mutex_t lock;
    void *tag;
    // Memory pool statistics
    umf_pool_stats_t stats;

    // ops should be the last due to possible change size in the future
    umf_memory_pool_ops_t ops;
} umf_memory_pool_t;

extern umf_ctl_node_t CTL_NODE(pool)[];

void umfPoolCtlDefaultsDestroy(void);

#ifdef __cplusplus
}
#endif

#endif /* UMF_MEMORY_POOL_INTERNAL_H */
