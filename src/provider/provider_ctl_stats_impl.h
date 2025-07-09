/*
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifdef UMF_PROVIDER_CTL_STATS_IMPL_H
#error This file should not be included more than once
#else
#define UMF_PROVIDER_CTL_STATS_IMPL_H 1

#ifndef CTL_PROVIDER_TYPE
#error "CTL_PROVIDER_TYPE must be defined"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "ctl/ctl_internal.h"
#include "utils/utils_assert.h"

static umf_result_t
CTL_READ_HANDLER(peak_memory)(void *ctx, umf_ctl_query_source_t source,
                              void *arg, size_t size,
                              umf_ctl_index_utlist_t *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)size, (void)indexes;

    size_t *arg_out = arg;
    CTL_PROVIDER_TYPE *provider = (CTL_PROVIDER_TYPE *)ctx;
    utils_atomic_load_acquire_size_t(&provider->stats.peak_memory, arg_out);
    return UMF_RESULT_SUCCESS;
}

static umf_result_t
CTL_READ_HANDLER(allocated_memory)(void *ctx, umf_ctl_query_source_t source,
                                   void *arg, size_t size,
                                   umf_ctl_index_utlist_t *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)size, (void)indexes;

    size_t *arg_out = arg;
    CTL_PROVIDER_TYPE *provider = (CTL_PROVIDER_TYPE *)ctx;
    utils_atomic_load_acquire_size_t(&provider->stats.allocated_memory,
                                     arg_out);
    return UMF_RESULT_SUCCESS;
}

static umf_result_t
CTL_RUNNABLE_HANDLER(reset)(void *ctx, umf_ctl_query_source_t source, void *arg,
                            size_t size, umf_ctl_index_utlist_t *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)indexes, (void)arg, (void)size;

    CTL_PROVIDER_TYPE *provider = (CTL_PROVIDER_TYPE *)ctx;
    size_t allocated;
    size_t current_peak;

    utils_atomic_load_acquire_size_t(&provider->stats.peak_memory,
                                     &current_peak);
    do {
        utils_atomic_load_acquire_size_t(&provider->stats.allocated_memory,
                                         &allocated);
    } while (!utils_compare_exchange_size_t(&provider->stats.peak_memory,
                                            &current_peak, &allocated));

    return UMF_RESULT_SUCCESS;
}

static const umf_ctl_node_t CTL_NODE(peak_memory)[] = {CTL_LEAF_RUNNABLE(reset),
                                                       CTL_NODE_END};

static const umf_ctl_node_t CTL_NODE(stats)[] = {
    CTL_LEAF_RO(allocated_memory), CTL_LEAF_RO(peak_memory),
    CTL_CHILD(peak_memory), CTL_LEAF_RUNNABLE(reset), CTL_NODE_END};

static inline void provider_ctl_stats_alloc(CTL_PROVIDER_TYPE *provider,
                                            size_t size) {
    size_t allocated =
        utils_fetch_and_add_size_t(&provider->stats.allocated_memory, size) +
        size;

    size_t peak;
    utils_atomic_load_acquire_size_t(&provider->stats.peak_memory, &peak);

    // If the compare-exchange fails, 'peak' is updated to the current value
    // of peak_memory. We then re-check whether allocated is still greater than
    // the updated peak value.
    while (allocated > peak &&
           !utils_compare_exchange_size_t(&provider->stats.peak_memory, &peak,
                                          &allocated)) {
        ;
    }
}

static inline void provider_ctl_stats_free(CTL_PROVIDER_TYPE *provider,
                                           size_t size) {
    utils_fetch_and_sub_size_t(&provider->stats.allocated_memory, size);
}

#ifdef __cplusplus
}
#endif

#endif /* UMF_PROVIDER_CTL_STATS_IMPL_H */
