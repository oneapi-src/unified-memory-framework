/*
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include "pool/pool_disjoint_internal.h"
#include "umf/base.h"
#include <stdio.h>
#include <string.h>

#include <ctl/ctl.h>
#include <umf/memory_pool.h>
#include <umf/memory_pool_ops.h>
#include <umf/memory_provider.h>

struct ctl disjoint_ctl_root;
static UTIL_ONCE_FLAG ctl_initialized = UTIL_ONCE_FLAG_INIT;

static int CTL_READ_HANDLER(name)(void *ctx, umf_ctl_query_source_t source,
                                  void *arg, size_t size,
                                  umf_ctl_index_utlist_t *indexes,
                                  const char *extra_name,
                                  umf_ctl_query_type_t queryType) {
    (void)source, (void)indexes, (void)queryType, (void)size;
    disjoint_pool_t *pool = (disjoint_pool_t *)ctx;
    if (strstr(extra_name, pool->params.name) != NULL) {
        strncpy(pool->params.name, (char *)arg,
                sizeof(pool->params.name) / sizeof(pool->params.name[0]));
    }
    return 0;
}

static const umf_ctl_node_t CTL_NODE(disjoint)[] = {CTL_LEAF_RO(name),
                                                    CTL_NODE_END};

static void initialize_disjoint_ctl(void) {
    CTL_REGISTER_MODULE(&disjoint_ctl_root, disjoint);
}

umf_result_t disjoint_pool_ctl(void *hPool, int operationType, const char *name,
                               void *arg, size_t size,
                               umf_ctl_query_type_t queryType) {
    (void)hPool;
    (void)operationType;
    (void)name;
    (void)arg;
    (void)size;
    (void)queryType;
    utils_init_once(&ctl_initialized, initialize_disjoint_ctl);

    const char *prefix = "disjoint.";
    const char *name_wo_prefix = strstr(name, "disjoint.");
    if ((name_wo_prefix = strstr(name, prefix)) == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    return ctl_query(&disjoint_ctl_root, hPool, CTL_QUERY_PROGRAMMATIC,
                     name_wo_prefix, CTL_QUERY_READ, arg, size);
}
