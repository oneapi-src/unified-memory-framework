/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <assert.h>
#include <stdlib.h>

#include <umf.h>
#include <umf/memspace.h>

// UMF_MEMSPACE_HIGHEST_CAPACITY requires HWLOC
// Additionally, it is currently unsupported on Win
#if defined(_WIN32) || defined(UMF_NO_HWLOC)

umf_const_memspace_handle_t umfMemspaceHighestCapacityGet(void) {
    // not supported
    return NULL;
}

#else // !defined(_WIN32) && !defined(UMF_NO_HWLOC)

#include "base_alloc_global.h"
#include "memspace_internal.h"
#include "memtarget_numa.h"
#include "topology.h"
#include "utils_concurrency.h"

static umf_result_t
umfMemspaceHighestCapacityCreate(umf_memspace_handle_t *hMemspace) {
    if (!hMemspace) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_const_memspace_handle_t hostAllMemspace = umfMemspaceHostAllGet();
    if (!hostAllMemspace) {
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    umf_memspace_handle_t highCapacityMemspace;
    umf_result_t ret = umfMemspaceClone(hostAllMemspace, &highCapacityMemspace);
    if (ret != UMF_RESULT_SUCCESS) {
        return ret;
    }

    ret = umfMemspaceSortDesc(highCapacityMemspace,
                              (umfGetPropertyFn)&umfMemtargetGetCapacity);
    if (ret != UMF_RESULT_SUCCESS) {
        return ret;
    }

    *hMemspace = highCapacityMemspace;

    return UMF_RESULT_SUCCESS;
}

static umf_memspace_handle_t UMF_MEMSPACE_HIGHEST_CAPACITY = NULL;
static UTIL_ONCE_FLAG UMF_MEMSPACE_HIGHEST_CAPACITY_INITIALIZED =
    UTIL_ONCE_FLAG_INIT;

void umfMemspaceHighestCapacityDestroy(void) {
    if (UMF_MEMSPACE_HIGHEST_CAPACITY) {
        umfMemspaceDestroy(UMF_MEMSPACE_HIGHEST_CAPACITY);
        UMF_MEMSPACE_HIGHEST_CAPACITY = NULL;

        // portable version of "UMF_MEMSPACE_HIGHEST_CAPACITY_INITIALIZED = UTIL_ONCE_FLAG_INIT;"
        static UTIL_ONCE_FLAG is_initialized = UTIL_ONCE_FLAG_INIT;
        memcpy(&UMF_MEMSPACE_HIGHEST_CAPACITY_INITIALIZED, &is_initialized,
               sizeof(UMF_MEMSPACE_HIGHEST_CAPACITY_INITIALIZED));
    }
}

static void umfMemspaceHighestCapacityInit(void) {
    umf_result_t ret =
        umfMemspaceHighestCapacityCreate(&UMF_MEMSPACE_HIGHEST_CAPACITY);
    assert(ret == UMF_RESULT_SUCCESS);
    (void)ret;
}

umf_const_memspace_handle_t umfMemspaceHighestCapacityGet(void) {
    utils_init_once(&UMF_MEMSPACE_HIGHEST_CAPACITY_INITIALIZED,
                    umfMemspaceHighestCapacityInit);
    return UMF_MEMSPACE_HIGHEST_CAPACITY;
}

#endif // !defined(_WIN32) && !defined(UMF_NO_HWLOC)
