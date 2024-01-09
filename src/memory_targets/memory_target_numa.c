/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <assert.h>
#include <numa.h>
#include <stdlib.h>

#include "../memory_pool_internal.h"
#include "memory_target_numa.h"
#include <umf/pools/pool_disjoint.h>
#include <umf/providers/provider_os_memory.h>

struct numa_memory_target_t {
    size_t id;
};

static umf_result_t numa_initialize(void *params, void **memTarget) {
    if (params == NULL || memTarget == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    struct umf_numa_memory_target_config_t *config =
        (struct umf_numa_memory_target_config_t *)params;

    struct numa_memory_target_t *numaTarget =
        malloc(sizeof(struct numa_memory_target_t));
    if (!numaTarget) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    numaTarget->id = config->id;
    *memTarget = numaTarget;
    return UMF_RESULT_SUCCESS;
}

static void numa_finalize(void *memTarget) { free(memTarget); }

static const umf_os_memory_provider_params_t
    UMF_OS_MEMORY_PROVIDER_PARAMS_DEFAULT = {
        // Visibility & protection
        .protection = UMF_PROTECTION_READ | UMF_PROTECTION_WRITE,
        .visibility = UMF_VISIBILITY_PRIVATE,

        // NUMA config
        .nodemask = NULL,
        .maxnode = 0, // TODO: numa_max_node/GetNumaHighestNodeNumber
        .numa_mode = UMF_NUMA_MODE_DEFAULT,
        .numa_flags = UMF_NUMA_FLAGS_STRICT, // TODO: determine default behavior

        // Logging
        .traces = 0, // TODO: parse env variable for log level?
};

static size_t numa_targets_get_maxnode(struct numa_memory_target_t **targets,
                                       size_t numTargets) {
    size_t maxNode = 0;
    for (size_t i = 0; i < numTargets; i++) {
        maxNode = maxNode > targets[i]->id ? maxNode : targets[i]->id;
    }
    return maxNode;
}

static struct bitmask *
numa_targets_create_nodemask(struct numa_memory_target_t **targets,
                             size_t numTargets) {
    assert(targets);
    size_t maxNode = numa_targets_get_maxnode(targets, numTargets);
    struct bitmask *mask = numa_bitmask_alloc(maxNode + 1);
    if (!mask) {
        return NULL;
    }

    for (size_t i = 0; i < numTargets; i++) {
        numa_bitmask_setbit(mask, targets[i]->id);
    }

    return mask;
}

static enum umf_result_t numa_memory_provider_create_from_memspace(
    umf_memspace_handle_t memspace, void **memTargets, size_t numTargets,
    umf_memspace_policy_handle_t policy,
    umf_memory_provider_handle_t *provider) {
    (void)memspace;
    // TODO: apply policy
    (void)policy;

    struct numa_memory_target_t **numaTargets =
        (struct numa_memory_target_t **)memTargets;

    // Create node mask from IDs
    struct bitmask *nodemask =
        numa_targets_create_nodemask(numaTargets, numTargets);

    umf_os_memory_provider_params_t params =
        UMF_OS_MEMORY_PROVIDER_PARAMS_DEFAULT;
    params.nodemask = nodemask->maskp;
    params.maxnode = nodemask->size;

    umf_memory_provider_handle_t numaProvider = NULL;
    enum umf_result_t ret = umfMemoryProviderCreate(&UMF_OS_MEMORY_PROVIDER_OPS,
                                                    &params, &numaProvider);
    numa_bitmask_free(nodemask);
    if (ret) {
        return ret;
    }

    *provider = numaProvider;

    return UMF_RESULT_SUCCESS;
}

static umf_result_t numa_pool_create_from_memspace(
    umf_memspace_handle_t memspace, void **memTargets, size_t numTargets,
    umf_memspace_policy_handle_t policy, umf_memory_pool_handle_t *pool) {
    (void)memspace;
    (void)memTargets;
    (void)numTargets;
    (void)policy;
    (void)pool;
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

struct umf_memory_target_ops_t UMF_MEMORY_TARGET_NUMA_OPS = {
    .version = UMF_VERSION_CURRENT,
    .initialize = numa_initialize,
    .finalize = numa_finalize,
    .pool_create_from_memspace = numa_pool_create_from_memspace,
    .memory_provider_create_from_memspace =
        numa_memory_provider_create_from_memspace};
