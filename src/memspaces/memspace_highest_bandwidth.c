/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <assert.h>
#include <ctype.h>
#include <hwloc.h>
#include <stdlib.h>

#include "base_alloc_global.h"
#include "memory_target_numa.h"
#include "memspace_internal.h"
#include "memspace_numa.h"
#include "topology.h"
#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_log.h"

static umf_result_t getBestBandwidthTarget(umf_memory_target_handle_t initiator,
                                           umf_memory_target_handle_t *nodes,
                                           size_t numNodes,
                                           umf_memory_target_handle_t *target) {
    size_t bestNodeIdx = 0;
    size_t bestBandwidth = 0;
    for (size_t nodeIdx = 0; nodeIdx < numNodes; nodeIdx++) {
        size_t bandwidth = 0;
        umf_result_t ret =
            umfMemoryTargetGetBandwidth(initiator, nodes[nodeIdx], &bandwidth);
        if (ret) {
            return ret;
        }

        if (bandwidth > bestBandwidth) {
            bestNodeIdx = nodeIdx;
            bestBandwidth = bandwidth;
        }
    }

    *target = nodes[bestNodeIdx];

    return UMF_RESULT_SUCCESS;
}

static umf_result_t
umfMemspaceHighestBandwidthCreate(umf_memspace_handle_t *hMemspace) {
    if (!hMemspace) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_memspace_handle_t hostAllMemspace = umfMemspaceHostAllGet();
    if (!hostAllMemspace) {
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    umf_memspace_handle_t highBandwidthMemspace = NULL;
    umf_result_t ret = umfMemspaceFilter(
        hostAllMemspace, getBestBandwidthTarget, &highBandwidthMemspace);
    if (ret != UMF_RESULT_SUCCESS) {
        // HWLOC could possibly return an 'EINVAL' error, which in this context
        // means that the HMAT is unavailable and we can't obtain the
        // 'bandwidth' value of any NUMA node.
        return ret;
    }

    *hMemspace = highBandwidthMemspace;
    return UMF_RESULT_SUCCESS;
}

static umf_memspace_handle_t UMF_MEMSPACE_HIGHEST_BANDWIDTH = NULL;
static UTIL_ONCE_FLAG UMF_MEMSPACE_HBW_INITIALIZED = UTIL_ONCE_FLAG_INIT;

void umfMemspaceHighestBandwidthDestroy(void) {
    if (UMF_MEMSPACE_HIGHEST_BANDWIDTH) {
        umfMemspaceDestroy(UMF_MEMSPACE_HIGHEST_BANDWIDTH);
        UMF_MEMSPACE_HIGHEST_BANDWIDTH = NULL;
    }
}

static void umfMemspaceHighestBandwidthInit(void) {
    umf_result_t ret =
        umfMemspaceHighestBandwidthCreate(&UMF_MEMSPACE_HIGHEST_BANDWIDTH);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR(
            "Creating the highest bandwidth memspace failed with a %u error\n",
            ret);
        assert(ret == UMF_RESULT_ERROR_NOT_SUPPORTED);
    }

#if defined(_WIN32) && !defined(UMF_SHARED_LIBRARY)
    atexit(umfMemspaceHighestBandwidthDestroy);
#endif
}

umf_memspace_handle_t umfMemspaceHighestBandwidthGet(void) {
    util_init_once(&UMF_MEMSPACE_HBW_INITIALIZED,
                   umfMemspaceHighestBandwidthInit);
    return UMF_MEMSPACE_HIGHEST_BANDWIDTH;
}
