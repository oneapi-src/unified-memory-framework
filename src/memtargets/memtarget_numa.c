/*
 *
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <assert.h>
#include <stdlib.h>

#include <umf/pools/pool_disjoint.h>
#include <umf/providers/provider_os_memory.h>

#include "../memory_pool_internal.h"
#include "base_alloc.h"
#include "base_alloc_global.h"
#include "mempolicy_internal.h"
#include "memtarget_numa.h"
#include "topology.h"
#include "utils_assert.h"
#include "utils_log.h"

struct numa_memtarget_t {
    unsigned physical_id;
};

static umf_result_t numa_initialize(void *params, void **memTarget) {
    if (params == NULL || memTarget == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    struct umf_numa_memtarget_config_t *config =
        (struct umf_numa_memtarget_config_t *)params;

    struct numa_memtarget_t *numaTarget =
        umf_ba_global_alloc(sizeof(struct numa_memtarget_t));
    if (!numaTarget) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    numaTarget->physical_id = config->physical_id;
    *memTarget = numaTarget;
    return UMF_RESULT_SUCCESS;
}

static void numa_finalize(void *memTarget) { umf_ba_global_free(memTarget); }

static umf_result_t numa_memory_provider_create_from_memspace(
    umf_const_memspace_handle_t memspace, void **memTargets, size_t numTargets,
    umf_const_mempolicy_handle_t policy,
    umf_memory_provider_handle_t *provider) {

    struct numa_memtarget_t **numaTargets =
        (struct numa_memtarget_t **)memTargets;

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

    if (policy) {
        switch (policy->type) {
        case UMF_MEMPOLICY_INTERLEAVE:
            params.numa_mode = UMF_NUMA_MODE_INTERLEAVE;
            params.part_size = policy->ops.interleave.part_size;
            break;
        case UMF_MEMPOLICY_BIND:
            params.numa_mode = UMF_NUMA_MODE_BIND;
            break;
        case UMF_MEMPOLICY_PREFERRED:
            params.numa_mode = UMF_NUMA_MODE_PREFERRED;
            break;
        case UMF_MEMPOLICY_SPLIT:
            params.numa_mode = UMF_NUMA_MODE_SPLIT;

            // compile time check to ensure we can just cast
            // umf_mempolicy_split_partition_t to
            // umf_numa_split_partition_t
            COMPILE_ERROR_ON(sizeof(umf_mempolicy_split_partition_t) !=
                             sizeof(umf_numa_split_partition_t));
            COMPILE_ERROR_ON(
                offsetof(umf_mempolicy_split_partition_t, weight) !=
                offsetof(umf_numa_split_partition_t, weight));
            COMPILE_ERROR_ON(
                offsetof(umf_mempolicy_split_partition_t, target) !=
                offsetof(umf_numa_split_partition_t, target));

            params.partitions =
                (umf_numa_split_partition_t *)policy->ops.split.part;
            params.partitions_len = policy->ops.split.part_len;
            break;
        default:
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
    } else {
        if (memspace == umfMemspaceHostAllGet()) {
            // For the default memspace, we use the default mode without any
            // call to mbind
            params.numa_mode = UMF_NUMA_MODE_DEFAULT;
        } else {
            params.numa_mode = UMF_NUMA_MODE_BIND;
        }
    }

    if (memspace == umfMemspaceHostAllGet() && policy == NULL) {
        // For default memspace with default policy we use all numa nodes so
        // simply left numa list empty
        params.numa_list_len = 0;
        params.numa_list = NULL;
    } else {
        params.numa_list =
            umf_ba_global_alloc(sizeof(*params.numa_list) * numNodesProvider);

        if (!params.numa_list) {
            return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        }

        for (size_t i = 0; i < numNodesProvider; i++) {
            params.numa_list[i] = numaTargets[i]->physical_id;
        }
        params.numa_list_len = numNodesProvider;
    }

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
    umf_const_memspace_handle_t memspace, void **memTargets, size_t numTargets,
    umf_const_mempolicy_handle_t policy, umf_memory_pool_handle_t *pool) {
    (void)memspace;
    (void)memTargets;
    (void)numTargets;
    (void)policy;
    (void)pool;
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

static umf_result_t numa_clone(void *memTarget, void **outMemTarget) {
    struct numa_memtarget_t *numaTarget = (struct numa_memtarget_t *)memTarget;
    struct numa_memtarget_t *newNumaTarget =
        umf_ba_global_alloc(sizeof(struct numa_memtarget_t));
    if (!newNumaTarget) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    newNumaTarget->physical_id = numaTarget->physical_id;
    *outMemTarget = newNumaTarget;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t numa_get_capacity(void *memTarget, size_t *capacity) {
    if (!memTarget || !capacity) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hwloc_topology_t topology = umfGetTopology();
    if (!topology) {
        return UMF_RESULT_ERROR_NOT_SUPPORTED;
    }

    hwloc_obj_t numaNode = hwloc_get_numanode_obj_by_os_index(
        topology, ((struct numa_memtarget_t *)memTarget)->physical_id);
    if (!numaNode) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (!numaNode->attr) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *capacity = numaNode->attr->numanode.local_memory;
    return UMF_RESULT_SUCCESS;
}

typedef enum memattr_type_t {
    MEMATTR_TYPE_BANDWIDTH,
    MEMATTR_TYPE_LATENCY
} memattr_type_t;

static size_t memattr_get_worst_value(memattr_type_t type) {
    switch (type) {
    case MEMATTR_TYPE_BANDWIDTH:
        return 0;
    case MEMATTR_TYPE_LATENCY:
        return SIZE_MAX;
    default:
        assert(0); // Should not be reachable
        return 0;
    }
}

static umf_result_t query_attribute_value(void *srcMemoryTarget,
                                          void *dstMemoryTarget, size_t *value,
                                          memattr_type_t type) {
    hwloc_topology_t topology = umfGetTopology();
    if (!topology) {
        LOG_PERR("Retrieving cached topology failed");
        return UMF_RESULT_ERROR_NOT_SUPPORTED;
    }

    hwloc_obj_t srcNumaNode = hwloc_get_obj_by_type(
        topology, HWLOC_OBJ_NUMANODE,
        ((struct numa_memtarget_t *)srcMemoryTarget)->physical_id);
    if (!srcNumaNode) {
        LOG_PERR("Getting HWLOC object by type failed");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hwloc_obj_t dstNumaNode = hwloc_get_obj_by_type(
        topology, HWLOC_OBJ_NUMANODE,
        ((struct numa_memtarget_t *)dstMemoryTarget)->physical_id);
    if (!dstNumaNode) {
        LOG_PERR("Getting HWLOC object by type failed");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    // Given NUMA nodes aren't local, HWLOC returns an error in such case.
    if (!hwloc_bitmap_intersects(srcNumaNode->cpuset, dstNumaNode->cpuset)) {
        // Since we want to skip such query, we return the worst possible
        // value for given memory attribute.
        LOG_PDEBUG("Testing whether two bitmaps intersect failed, using the "
                   "worst value");
        *value = memattr_get_worst_value(type);
        return UMF_RESULT_SUCCESS;
    }

    enum hwloc_memattr_id_e hwlocMemAttrType = INT_MAX;
    switch (type) {
    case MEMATTR_TYPE_BANDWIDTH:
        hwlocMemAttrType = HWLOC_MEMATTR_ID_BANDWIDTH;
        break;
    case MEMATTR_TYPE_LATENCY:
        hwlocMemAttrType = HWLOC_MEMATTR_ID_LATENCY;
        break;
    default:
        assert(0); // Shouldn't be reachable.
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    struct hwloc_location initiator = {.location.cpuset = srcNumaNode->cpuset,
                                       .type = HWLOC_LOCATION_TYPE_CPUSET};

    hwloc_uint64_t memAttrValue = 0;
    int ret = hwloc_memattr_get_value(topology, hwlocMemAttrType, dstNumaNode,
                                      &initiator, 0, &memAttrValue);
    if (ret) {
        LOG_PERR("Getting an attribute value for a specific target NUMA node "
                 "failed");
        return (errno == EINVAL) ? UMF_RESULT_ERROR_NOT_SUPPORTED
                                 : UMF_RESULT_ERROR_UNKNOWN;
    }

    *value = memAttrValue;

    return UMF_RESULT_SUCCESS;
}

static umf_result_t numa_get_bandwidth(void *srcMemoryTarget,
                                       void *dstMemoryTarget,
                                       size_t *bandwidth) {
    if (!srcMemoryTarget || !dstMemoryTarget || !bandwidth) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_result_t ret = query_attribute_value(srcMemoryTarget, dstMemoryTarget,
                                             bandwidth, MEMATTR_TYPE_BANDWIDTH);
    if (ret) {
        LOG_ERR("Retrieving bandwidth for initiator node %u to node %u failed.",
                ((struct numa_memtarget_t *)srcMemoryTarget)->physical_id,
                ((struct numa_memtarget_t *)dstMemoryTarget)->physical_id);
        return ret;
    }

    return UMF_RESULT_SUCCESS;
}

static umf_result_t numa_get_latency(void *srcMemoryTarget,
                                     void *dstMemoryTarget, size_t *latency) {
    if (!srcMemoryTarget || !dstMemoryTarget || !latency) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_result_t ret = query_attribute_value(srcMemoryTarget, dstMemoryTarget,
                                             latency, MEMATTR_TYPE_LATENCY);
    if (ret) {
        LOG_ERR("Retrieving latency for initiator node %u to node %u failed.",
                ((struct numa_memtarget_t *)srcMemoryTarget)->physical_id,
                ((struct numa_memtarget_t *)dstMemoryTarget)->physical_id);
        return ret;
    }

    return UMF_RESULT_SUCCESS;
}

static umf_result_t numa_get_type(void *memTarget, umf_memtarget_type_t *type) {
    if (!memTarget || !type) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *type = UMF_MEMTARGET_TYPE_NUMA;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t numa_get_id(void *memTarget, unsigned *id) {
    if (!memTarget || !id) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *id = ((struct numa_memtarget_t *)memTarget)->physical_id;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t numa_compare(void *memTarget, void *otherMemTarget,
                                 int *result) {
    if (!memTarget || !otherMemTarget || !result) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    struct numa_memtarget_t *numaTarget = (struct numa_memtarget_t *)memTarget;
    struct numa_memtarget_t *otherNumaTarget =
        (struct numa_memtarget_t *)otherMemTarget;

    *result = numaTarget->physical_id != otherNumaTarget->physical_id;
    return UMF_RESULT_SUCCESS;
}

struct umf_memtarget_ops_t UMF_MEMTARGET_NUMA_OPS = {
    .version = UMF_VERSION_CURRENT,
    .initialize = numa_initialize,
    .finalize = numa_finalize,
    .pool_create_from_memspace = numa_pool_create_from_memspace,
    .clone = numa_clone,
    .get_capacity = numa_get_capacity,
    .get_bandwidth = numa_get_bandwidth,
    .get_latency = numa_get_latency,
    .get_type = numa_get_type,
    .get_id = numa_get_id,
    .compare = numa_compare,
    .memory_provider_create_from_memspace =
        numa_memory_provider_create_from_memspace};
