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
#include <stdlib.h>

#include <umf.h>
#include <umf/memspace.h>

// UMF_MEMSPACE_LOWEST_LATENCY requires HWLOC
// Additionally, it is currently unsupported on Win
#if defined(_WIN32) || defined(UMF_NO_HWLOC)

umf_const_memspace_handle_t umfMemspaceLowestLatencyGet(void) {
    // not supported
    return NULL;
}

#else // !defined(_WIN32) && !defined(UMF_NO_HWLOC)

#include "base_alloc_global.h"
#include "memspace_internal.h"
#include "memtarget_numa.h"
#include "topology.h"
#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_log.h"

static umf_result_t getBestLatencyTarget(umf_memtarget_handle_t initiator,
                                         umf_memtarget_handle_t *nodes,
                                         size_t numNodes,
                                         umf_memtarget_handle_t *target) {
    size_t bestNodeIdx = 0;
    size_t bestLatency = SIZE_MAX;
    for (size_t nodeIdx = 0; nodeIdx < numNodes; nodeIdx++) {
        size_t latency = SIZE_MAX;
        umf_result_t ret =
            umfMemtargetGetLatency(initiator, nodes[nodeIdx], &latency);
        if (ret) {
            return ret;
        }

        if (latency < bestLatency) {
            bestNodeIdx = nodeIdx;
            bestLatency = latency;
        }
    }

    *target = nodes[bestNodeIdx];

    return UMF_RESULT_SUCCESS;
}

static umf_result_t
umfMemspaceLowestLatencyCreate(umf_memspace_handle_t *hMemspace) {
    if (!hMemspace) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_const_memspace_handle_t hostAllMemspace = umfMemspaceHostAllGet();
    if (!hostAllMemspace) {
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    umf_memspace_handle_t lowLatencyMemspace = NULL;
    umf_result_t ret = umfMemspaceFilter(hostAllMemspace, getBestLatencyTarget,
                                         &lowLatencyMemspace);
    if (ret != UMF_RESULT_SUCCESS) {
        // HWLOC could possibly return an 'EINVAL' error, which in this context
        // means that the HMAT is unavailable and we can't obtain the
        // 'latency' value of any NUMA node.
        return ret;
    }

    *hMemspace = lowLatencyMemspace;
    return UMF_RESULT_SUCCESS;
}

static umf_memspace_handle_t UMF_MEMSPACE_LOWEST_LATENCY = NULL;
static UTIL_ONCE_FLAG UMF_MEMSPACE_LOWEST_LATENCY_INITIALIZED =
    UTIL_ONCE_FLAG_INIT;

void umfMemspaceLowestLatencyDestroy(void) {
    if (UMF_MEMSPACE_LOWEST_LATENCY) {
        umfMemspaceDestroy(UMF_MEMSPACE_LOWEST_LATENCY);
        UMF_MEMSPACE_LOWEST_LATENCY = NULL;
    }
}

static void umfMemspaceLowestLatencyInit(void) {
    umf_result_t ret =
        umfMemspaceLowestLatencyCreate(&UMF_MEMSPACE_LOWEST_LATENCY);
    if (ret != UMF_RESULT_SUCCESS) {
        LOG_ERR(
            "Creating the lowest latency memspace failed with the error: %u",
            ret);
        assert(ret == UMF_RESULT_ERROR_NOT_SUPPORTED);
    }

#if defined(_WIN32) && !defined(UMF_SHARED_LIBRARY)
    atexit(umfMemspaceLowestLatencyDestroy);
#endif
}

umf_const_memspace_handle_t umfMemspaceLowestLatencyGet(void) {
    utils_init_once(&UMF_MEMSPACE_LOWEST_LATENCY_INITIALIZED,
                    umfMemspaceLowestLatencyInit);
    return UMF_MEMSPACE_LOWEST_LATENCY;
}

#endif // !defined(_WIN32) && !defined(UMF_NO_HWLOC)
