/*
 *
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "umf/base.h"
#include <stdbool.h>
#include <stdio.h>

#include <umf/experimental/ctl.h>
#include <umf/memory_pool.h>
#include <umf/memory_provider.h>
#include <umf/pools/pool_disjoint.h>
#include <umf/providers/provider_os_memory.h>

static void print_provider_stats(const char *stage,
                                 umf_memory_provider_handle_t provider,
                                 const char *provider_name) {
    size_t outstanding = 0;
    size_t peak = 0;

    umf_result_t res =
        umfCtlGet("umf.provider.by_handle.{}.stats.allocated_memory",
                  &outstanding, sizeof(outstanding), provider);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "%s: failed to read provider allocated memory (error %d)\n",
                stage, (int)res);
        return;
    }

    /* you can also pass any nodes through va args by using {} */
    res = umfCtlGet("umf.provider.by_handle.{}.stats.{}", &peak, sizeof(peak),
                    provider, "peak_memory");
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "%s: failed to read provider peak memory (error %d)\n",
                stage, (int)res);
        return;
    }

    printf("%s (%s): outstanding=%zu bytes, peak=%zu bytes\n", stage,
           provider_name, outstanding, peak);
}

/* Provide tutorial guidance when disjoint pool counters require tracing. */
static bool report_pool_stat_failure(const char *label,
                                     int required_trace_level,
                                     umf_result_t res) {
    if (res == UMF_RESULT_SUCCESS) {
        return false;
    }

    if (res == UMF_RESULT_ERROR_NOT_SUPPORTED) {
        int hint_level = required_trace_level;
        const char *reason = "verbose logging";

        if (hint_level <= 1) {
            hint_level = 1;
            reason = "slab statistics";
        } else if (hint_level == 2) {
            reason = "allocation counters";
        } else if (hint_level < 3) {
            hint_level = 2;
            reason = "allocation counters";
        } else {
            hint_level = 3;
        }

        fprintf(
            stderr,
            "Cannot read %s because disjoint pool tracing level %d is "
            "required. "
            "This example do not set pool_trace so you can enable it through "
            "env variable.\n"
            "Set UMF_CONF=\"umf.pool.default.disjoint.params.pool_trace=%d\" "
            "before running to enable %s%s.\n",
            label, hint_level, hint_level, reason,
            hint_level < 3 ? " (level 3 also enables verbose logging)" : "");
    } else {
        fprintf(stderr, "Failed to read %s (error %d)\n", label, (int)res);
    }

    return true;
}

static void print_pool_stat_by_handle(const char *label,
                                      umf_memory_pool_handle_t pool,
                                      const char *stat_node,
                                      int required_trace_level) {
    size_t value = 0;
    /* Surround the {} placeholder with literal segments so CTL resolves
     * whichever pool handle the allocator hands back. */
    umf_result_t res = umfCtlGet("umf.pool.by_handle.{}.stats.{}", &value,
                                 sizeof(value), pool, stat_node);
    if (report_pool_stat_failure(label, required_trace_level, res)) {
        return;
    }

    printf("%s: %zu\n", label, value);
}

static void print_pool_bucket_stat_by_name(const char *label,
                                           const char *pool_name,
                                           size_t bucket_index,
                                           const char *stat_node,
                                           int required_trace_level) {
    size_t value = 0;
    /* Anchor the pool label with by_name while {} wildcards cover the ordinal
     * and statistic nodes to highlight mixed selectors. */
    umf_result_t res =
        umfCtlGet("umf.pool.by_name.{}.buckets.{}.stats.{}", &value,
                  sizeof(value), pool_name, bucket_index, stat_node);

    if (report_pool_stat_failure(label, required_trace_level, res)) {
        return;
    }

    printf("%s: %zu\n", label, value);
}

#define pool_name "ctl_stats_pool"
int main(void) {
    const size_t provider_allocation_size = 64 * 1024;
    const size_t pool_allocation_size = 4096;
    const char *provider_name = NULL;
    void *pool_memory = NULL;
    umf_result_t res = UMF_RESULT_SUCCESS;

    const umf_memory_provider_ops_t *provider_ops = umfOsMemoryProviderOps();
    umf_os_memory_provider_params_handle_t os_params = NULL;
    umf_memory_provider_handle_t provider = NULL;
    umf_disjoint_pool_params_handle_t disjoint_params = NULL;
    umf_memory_pool_handle_t pool = NULL;

    res = umfOsMemoryProviderParamsCreate(&os_params);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "Failed to create OS memory provider params (error %d)\n",
                (int)res);
        return -1;
    }

    res = umfMemoryProviderCreate(provider_ops, os_params, &provider);
    umfOsMemoryProviderParamsDestroy(os_params);
    os_params = NULL;
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to create OS memory provider (error %d)\n",
                (int)res);
        return -1;
    }

    res = umfMemoryProviderGetName(provider, &provider_name);
    if (res != UMF_RESULT_SUCCESS || provider_name == NULL) {
        provider_name = "OS";
    }

    print_provider_stats("Provider stats before allocation", provider,
                         provider_name);

    void *provider_memory = NULL;
    res = umfMemoryProviderAlloc(provider, provider_allocation_size, 0,
                                 &provider_memory);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Provider allocation failed (error %d)\n", (int)res);
        goto cleanup;
    }

    print_provider_stats("Provider stats after allocation", provider,
                         provider_name);

    res = umfMemoryProviderFree(provider, provider_memory,
                                provider_allocation_size);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Provider free failed (error %d)\n", (int)res);
        goto cleanup;
    }
    provider_memory = NULL;

    print_provider_stats("Provider stats after free", provider, provider_name);

    res = umfCtlExec("umf.provider.by_handle.{}.stats.peak_memory.reset", NULL,
                     0, provider);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to reset provider peak memory (error %d)\n",
                (int)res);
        goto cleanup;
    }

    print_provider_stats("Provider stats after peak reset", provider,
                         provider_name);

    const umf_memory_pool_ops_t *pool_ops = umfDisjointPoolOps();
    res = umfDisjointPoolParamsCreate(&disjoint_params);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to create disjoint pool params (error %d)\n",
                (int)res);
        goto cleanup;
    }

    /* set name of the pool so we can easly ref it by using name */
    res = umfDisjointPoolParamsSetName(disjoint_params, pool_name);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to name disjoint pool (error %d)\n", (int)res);
        goto cleanup;
    }

    res = umfPoolCreate(pool_ops, provider, disjoint_params, 0, &pool);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to create disjoint pool (error %d)\n",
                (int)res);
        goto cleanup;
    }

    pool_memory = umfPoolMalloc(pool, pool_allocation_size);
    if (pool_memory == NULL) {
        fprintf(stderr, "Disjoint pool allocation failed\n");
        goto cleanup;
    }

    print_pool_stat_by_handle("Disjoint pool used_memory", pool, "used_memory",
                              0);
    print_pool_stat_by_handle("Disjoint pool curr_slabs_in_use", pool,
                              "curr_slabs_in_use", 1);
    print_pool_stat_by_handle("Disjoint pool alloc_num", pool, "alloc_num", 2);

    size_t pool_name_count = 0;

    res = umfCtlGet("umf.pool.by_name.{}.count", &pool_name_count,
                    sizeof(pool_name_count), pool_name);

    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to read pool count (error %d)\n", (int)res);
        goto cleanup;
    }
    printf("There is %zu pools with name %s\n", pool_name_count, pool_name);
    size_t bucket_count = 0;

    // you can put pool_name directly in ctl string without {} if you want
    res = umfCtlGet("umf.pool.by_name." pool_name ".buckets.count",
                    &bucket_count, sizeof(bucket_count));

    for (size_t bucket = 0; bucket < bucket_count; bucket++) {
        size_t bucket_size = 0;
        // after pool name you can add pool index if there are multiple pools with
        // the same name, if there is only one it is safe to omit it
        // but still you can provide it
        res = umfCtlGet("umf.pool.by_name.{}.0.buckets.{}.size", &bucket_size,
                        sizeof(bucket_size), pool_name, bucket);
        if (res != UMF_RESULT_SUCCESS) {
            fprintf(stderr, "Failed to read bucket size (error %d)\n",
                    (int)res);
            goto cleanup;
        }

        if (bucket_size == pool_allocation_size) {
            printf("Disjoint pool bucket[%zu] size: %zu bytes\n", bucket,
                   bucket_size);
            print_pool_bucket_stat_by_name("Disjoint pool bucket alloc_num",
                                           pool_name, bucket, "alloc_num", 2);
            print_pool_bucket_stat_by_name(
                "Disjoint pool bucket curr_slabs_in_use", pool_name, bucket,
                "curr_slabs_in_use", 1);
            goto cleanup;
        }
    }

cleanup:
    if (pool_memory) {
        umfFree(pool_memory);
    }

    if (pool) {
        umfPoolDestroy(pool);
    }
    if (disjoint_params) {
        umfDisjointPoolParamsDestroy(disjoint_params);
    }
    if (provider_memory) {
        umfMemoryProviderFree(provider, provider_memory,
                              provider_allocation_size);
    }
    if (provider) {
        umfMemoryProviderDestroy(provider);
    }

    return 0;
}
