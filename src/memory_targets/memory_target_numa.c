/*
 *
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <assert.h>
#include <hwloc.h>
#include <stdlib.h>

#include <umf/pools/pool_disjoint.h>
#include <umf/providers/provider_os_memory.h>

#include "../memory_pool_internal.h"
#include "base_alloc.h"
#include "base_alloc_global.h"
#include "memory_target_numa.h"
#include "topology.h"
#include "utils_log.h"

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
    (void)memspace;
    (void)memTargets;
    (void)numTargets;
    (void)policy;
    (void)pool;
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
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

static umf_result_t numa_get_bandwidth(void *srcMemoryTarget,
                                       void *dstMemoryTarget,
                                       size_t *bandwidth) {
    hwloc_topology_t topology = umfGetTopology();
    if (!topology) {
        return UMF_RESULT_ERROR_NOT_SUPPORTED;
    }

    hwloc_obj_t srcNumaNode = hwloc_get_obj_by_type(
        topology, HWLOC_OBJ_NUMANODE,
        ((struct numa_memory_target_t *)srcMemoryTarget)->physical_id);
    if (!srcNumaNode) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hwloc_obj_t dstNumaNode = hwloc_get_obj_by_type(
        topology, HWLOC_OBJ_NUMANODE,
        ((struct numa_memory_target_t *)dstMemoryTarget)->physical_id);
    if (!dstNumaNode) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    // Given NUMA nodes aren't local, HWLOC returns an error in such case.
    if (!hwloc_bitmap_intersects(srcNumaNode->cpuset, dstNumaNode->cpuset)) {
        *bandwidth = 0;
        return UMF_RESULT_SUCCESS;
    }

    struct hwloc_location initiator = {.location.cpuset = srcNumaNode->cpuset,
                                       .type = HWLOC_LOCATION_TYPE_CPUSET};
    hwloc_uint64_t value = 0;
    int ret = hwloc_memattr_get_value(topology, HWLOC_MEMATTR_ID_BANDWIDTH,
                                      dstNumaNode, &initiator, 0, &value);
    if (ret) {
        LOG_ERR("Retrieving bandwidth for initiator node %u to node %u failed.",
                srcNumaNode->os_index, dstNumaNode->os_index);
        return (errno == EINVAL) ? UMF_RESULT_ERROR_NOT_SUPPORTED
                                 : UMF_RESULT_ERROR_UNKNOWN;
    }

    *bandwidth = value;
    return UMF_RESULT_SUCCESS;
}

struct umf_memory_target_ops_t UMF_MEMORY_TARGET_NUMA_OPS = {
    .version = UMF_VERSION_CURRENT,
    .initialize = numa_initialize,
    .finalize = numa_finalize,
    .pool_create_from_memspace = numa_pool_create_from_memspace,
    .clone = numa_clone,
    .get_capacity = numa_get_capacity,
    .get_bandwidth = numa_get_bandwidth,
    .memory_provider_create_from_memspace =
        numa_memory_provider_create_from_memspace};
