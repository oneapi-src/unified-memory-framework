/*
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <assert.h>
#include <hwloc.h>
#include <stdlib.h>

#ifdef UMF_BUILD_LIBUMF_POOL_SCALABLE
#include <umf/pools/pool_scalable.h>
#endif

#include <umf/pools/pool_proxy.h>
#include <umf/providers/provider_os_memory.h>

#include "../memory_pool_internal.h"
#include "base_alloc.h"
#include "base_alloc_global.h"
#include "memory_target_numa.h"
#include "topology.h"

struct numa_memory_target_t {
    unsigned physical_id;
};

static umf_result_t numa_initialize(void *params, void **memTarget) {
    if (params == NULL || memTarget == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    struct umf_numa_memory_target_config_t *config =
        (struct umf_numa_memory_target_config_t *)params;

    struct numa_memory_target_t *numaTarget =
        umf_ba_global_alloc(sizeof(struct numa_memory_target_t));
    if (!numaTarget) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    numaTarget->physical_id = config->physical_id;
    *memTarget = numaTarget;
    return UMF_RESULT_SUCCESS;
}

static void numa_finalize(void *memTarget) { umf_ba_global_free(memTarget); }

static umf_result_t numa_memory_provider_create_from_memspace(
    umf_memspace_handle_t memspace, void **memTargets, size_t numTargets,
    umf_memspace_policy_handle_t policy,
    umf_memory_provider_handle_t *provider) {
    // TODO: apply policy
    (void)policy;
    struct numa_memory_target_t **numaTargets =
        (struct numa_memory_target_t **)memTargets;

    size_t numNodesProvider;

    if (memspace == umfMemspaceHighestCapacityGet()) {
        // Pass only a single node to provider for now.
        // TODO: change this once we implement memspace policies
        numNodesProvider = 1;
    } else {
        numNodesProvider = numTargets;
    }

    if (numNodesProvider == 0) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_os_memory_provider_params_t params = umfOsMemoryProviderParamsDefault();
    params.numa_list =
        umf_ba_global_alloc(sizeof(*params.numa_list) * numNodesProvider);

    if (!params.numa_list) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    for (size_t i = 0; i < numNodesProvider; i++) {
        params.numa_list[i] = numaTargets[i]->physical_id;
    }

    params.numa_list_len = numNodesProvider;
    params.numa_mode = UMF_NUMA_MODE_BIND;

    umf_memory_provider_handle_t numaProvider = NULL;
    int ret = umfMemoryProviderCreate(umfOsMemoryProviderOps(), &params,
                                      &numaProvider);

    umf_ba_global_free(params.numa_list);

    if (ret) {
        return ret;
    }

    *provider = numaProvider;

    return UMF_RESULT_SUCCESS;
}

static umf_result_t numa_pool_create_from_memspace(
    umf_memspace_handle_t memspace, void **memTargets, size_t numTargets,
    umf_memspace_policy_handle_t policy, umf_memory_pool_handle_t *pool) {

    umf_memory_provider_handle_t numa_provider;
    umf_result_t umf_result = numa_memory_provider_create_from_memspace(
        memspace, memTargets, numTargets, policy, &numa_provider);
    if (umf_result != UMF_RESULT_SUCCESS) {
        return umf_result;
    }

    umf_memory_pool_handle_t numa_pool;

#ifdef UMF_BUILD_LIBUMF_POOL_SCALABLE
    umf_result = umfPoolCreate(umfScalablePoolOps(), numa_provider, NULL,
                               UMF_POOL_CREATE_FLAG_OWN_PROVIDER, &numa_pool);
#else
    umf_result = UMF_RESULT_ERROR_NOT_SUPPORTED;
#endif

    if (umf_result != UMF_RESULT_SUCCESS) {
        umfMemoryProviderDestroy(numa_provider);
        return umf_result;
    }

    *pool = numa_pool;

    return umf_result;
}

static umf_result_t numa_clone(void *memTarget, void **outMemTarget) {
    struct numa_memory_target_t *numaTarget =
        (struct numa_memory_target_t *)memTarget;
    struct numa_memory_target_t *newNumaTarget =
        umf_ba_global_alloc(sizeof(struct numa_memory_target_t));
    if (!newNumaTarget) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    newNumaTarget->physical_id = numaTarget->physical_id;
    *outMemTarget = newNumaTarget;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t numa_get_capacity(void *memTarget, size_t *capacity) {
    hwloc_topology_t topology = umfGetTopology();
    if (!topology) {
        return UMF_RESULT_ERROR_NOT_SUPPORTED;
    }

    hwloc_obj_t numaNode = hwloc_get_numanode_obj_by_os_index(
        topology, ((struct numa_memory_target_t *)memTarget)->physical_id);
    if (!numaNode) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (!numaNode->attr) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *capacity = numaNode->attr->numanode.local_memory;
    return UMF_RESULT_SUCCESS;
}

struct umf_memory_target_ops_t UMF_MEMORY_TARGET_NUMA_OPS = {
    .version = UMF_VERSION_CURRENT,
    .initialize = numa_initialize,
    .finalize = numa_finalize,
    .pool_create_from_memspace = numa_pool_create_from_memspace,
    .clone = numa_clone,
    .get_capacity = numa_get_capacity,
    .memory_provider_create_from_memspace =
        numa_memory_provider_create_from_memspace};
