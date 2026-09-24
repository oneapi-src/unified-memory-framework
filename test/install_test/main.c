/*
 *
 * Copyright (C) 2026 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <stdio.h>

#ifdef UMF_TEST_LINK_USER_HWLOC
#include <hwloc.h>
#endif

#include <umf.h>
#include <umf/memory_provider.h>
#include <umf/providers/provider_os_memory.h>

#ifdef UMF_TEST_LINK_USER_HWLOC
// The user's hwloc must keep working next to the copy embedded in UMF.
static int use_user_hwloc(void) {
    hwloc_topology_t topology;

    if (hwloc_get_api_version() != HWLOC_API_VERSION) {
        fprintf(stderr,
                "hwloc API version mismatch: runtime 0x%x, header 0x%x\n",
                hwloc_get_api_version(), HWLOC_API_VERSION);
        return 1;
    }

    if (hwloc_topology_init(&topology) != 0) {
        fprintf(stderr, "hwloc_topology_init failed\n");
        return 1;
    }

    int ret = hwloc_topology_load(topology);
    hwloc_topology_destroy(topology);
    if (ret != 0) {
        fprintf(stderr, "hwloc_topology_load failed\n");
        return 1;
    }

    return 0;
}
#endif

// The OS memory provider pulls hwloc symbols into the link of a static UMF.
int main(void) {
    umf_os_memory_provider_params_handle_t params = NULL;
    umf_memory_provider_handle_t provider = NULL;
    void *ptr = NULL;
    const size_t size = 4096;
    int ret = 1;

#ifdef UMF_TEST_LINK_USER_HWLOC
    if (use_user_hwloc() != 0) {
        return 1;
    }
#endif

    if (umfOsMemoryProviderParamsCreate(&params) != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "umfOsMemoryProviderParamsCreate failed\n");
        return 1;
    }

    if (umfMemoryProviderCreate(umfOsMemoryProviderOps(), params, &provider) !=
        UMF_RESULT_SUCCESS) {
        fprintf(stderr, "umfMemoryProviderCreate failed\n");
        goto err_params;
    }

    if (umfMemoryProviderAlloc(provider, size, 0, &ptr) != UMF_RESULT_SUCCESS ||
        ptr == NULL) {
        fprintf(stderr, "umfMemoryProviderAlloc failed\n");
        goto err_provider;
    }

    ((char *)ptr)[0] = 1;

    if (umfMemoryProviderFree(provider, ptr, size) != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "umfMemoryProviderFree failed\n");
        goto err_provider;
    }

    ret = 0;

err_provider:
    umfMemoryProviderDestroy(provider);
err_params:
    umfOsMemoryProviderParamsDestroy(params);
    return ret;
}
