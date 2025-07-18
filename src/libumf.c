/*
 *
 * Copyright (C) 2024-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <stdarg.h>
#include <stddef.h>
#include <string.h>

#include "base_alloc_global.h"
#include "ipc_cache.h"
#include "memory_pool_internal.h"
#include "memory_provider_internal.h"
#include "memspace_internal.h"
#include "pool/pool_scalable_internal.h"
#include "provider_cuda_internal.h"
#include "provider_level_zero_internal.h"
#include "provider_tracking.h"
#include "topology.h"
#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_log.h"

umf_memory_tracker_handle_t TRACKER = NULL;

static uint64_t umfRefCount = 0;
static utils_mutex_t initMutex;
static UTIL_ONCE_FLAG initMutexOnce = UTIL_ONCE_FLAG_INIT;

static void initialize_init_mutex(void) { utils_mutex_init(&initMutex); }

static umf_ctl_node_t CTL_NODE(umf)[] = {CTL_CHILD(provider), CTL_CHILD(pool),
                                         CTL_NODE_END};

void initialize_global_ctl(void) { CTL_REGISTER_MODULE(NULL, umf); }

umf_result_t umfInit(void) {
    utils_init_once(&initMutexOnce, initialize_init_mutex);

    utils_mutex_lock(&initMutex);

    if (umfRefCount == 0) {
        utils_log_init();
        umf_result_t umf_result = umfMemoryTrackerCreate(&TRACKER);
        if (umf_result != UMF_RESULT_SUCCESS) {
            LOG_ERR("Failed to create memory tracker");
            utils_mutex_unlock(&initMutex);
            return umf_result;
        }

        LOG_DEBUG("UMF tracker created");

        umf_result = umfIpcCacheGlobalInit();
        if (umf_result != UMF_RESULT_SUCCESS) {
            LOG_ERR("Failed to initialize IPC cache");
            umfMemoryTrackerDestroy(TRACKER);
            utils_mutex_unlock(&initMutex);
            return umf_result;
        }

        LOG_DEBUG("UMF IPC cache initialized");
        initialize_global_ctl();
    }

    umfRefCount++;
    utils_mutex_unlock(&initMutex);

    if (TRACKER) {
        LOG_DEBUG("UMF library initialized");
    }

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfTearDown(void) {
    utils_init_once(&initMutexOnce, initialize_init_mutex);

    utils_mutex_lock(&initMutex);
    if (umfRefCount == 0) {
        utils_mutex_unlock(&initMutex);
        return UMF_RESULT_SUCCESS;
    }

    if (--umfRefCount == 0) {
#if !defined(_WIN32)
        umfMemspaceHostAllDestroy();
        umfMemspaceHighestCapacityDestroy();
        umfMemspaceHighestBandwidthDestroy();
        umfMemspaceLowestLatencyDestroy();
        umfDestroyTopology();
#endif
        umfIpcCacheGlobalTearDown();

        if (utils_is_running_in_proxy_lib_with_size_threshold()) {
            // We cannot destroy the TRACKER nor the base allocator
            // when we are running in the proxy library with a size threshold,
            // because it could result in calling the system free()
            // with an invalid pointer and a segfault.
            goto fini_umfTearDown;
        }

        // make sure TRACKER is not used after being destroyed
        umf_memory_tracker_handle_t t = TRACKER;
        TRACKER = NULL;
        umfMemoryTrackerDestroy(t);
        LOG_DEBUG("UMF tracker destroyed");

        umf_ba_destroy_global();
        LOG_DEBUG("UMF base allocator destroyed");

    fini_umfTearDown:
        fini_ze_global_state();
        fini_cu_global_state();
        fini_tbb_global_state();
        LOG_DEBUG("UMF library finalized");
    }
    utils_mutex_unlock(&initMutex);
    return UMF_RESULT_SUCCESS;
}

int umfGetCurrentVersion(void) { return UMF_VERSION_CURRENT; }

umf_result_t umfCtlGet(const char *name, void *arg, size_t size, ...) {
    // ctx can be NULL when getting defaults
    if (name == NULL || arg == NULL || size == 0) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    va_list args;
    va_start(args, size);

    umf_result_t ret = ctl_query(NULL, NULL, CTL_QUERY_PROGRAMMATIC, name,
                                 CTL_QUERY_READ, arg, size, args);
    va_end(args);
    return ret;
}

umf_result_t umfCtlSet(const char *name, void *arg, size_t size, ...) {
    // ctx can be NULL when setting defaults
    if (name == NULL || arg == NULL || size == 0) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    va_list args;
    va_start(args, size);
    umf_result_t ret = ctl_query(NULL, NULL, CTL_QUERY_PROGRAMMATIC, name,
                                 CTL_QUERY_WRITE, arg, size, args);
    va_end(args);
    return ret;
}

umf_result_t umfCtlExec(const char *name, void *arg, size_t size, ...) {
    // arg can be NULL when executing a command
    // ctx can be NULL when executing defaults
    // size can depends on the arg
    if (name == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if ((arg == NULL && size != 0) || (arg != NULL && size == 0)) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    va_list args;
    va_start(args, size);

    umf_result_t ret = ctl_query(NULL, NULL, CTL_QUERY_PROGRAMMATIC, name,
                                 CTL_QUERY_RUNNABLE, arg, size, args);
    va_end(args);
    return ret;
}
