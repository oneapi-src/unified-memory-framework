
/*
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <umf.h>
#include <umf/memory_provider.h>
#include <umf/memory_provider_ops.h>

#include "utils_log.h"

umf_memory_provider_ops_t *umfCoarseMemoryProviderOps(void) {
    LOG_ERR("Coarse Provider is deprecated!");
    return NULL;
}

typedef struct coarse_memory_provider_stats_t {
    size_t alloc_size;
    size_t used_size;
    size_t num_upstream_blocks;
    size_t num_all_blocks;
    size_t num_free_blocks;
} coarse_memory_provider_stats_t;

coarse_memory_provider_stats_t
umfCoarseMemoryProviderGetStats(umf_memory_provider_handle_t provider) {
    (void)provider;
    LOG_ERR("Coarse Provider is deprecated!");
    coarse_memory_provider_stats_t ret = {0};
    return ret;
}
