/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <umf/mempolicy.h>
#include <umf/memspace.h>

#include <numa.h>
#include <numaif.h>
#include <stdio.h>
#include <string.h>

#include "utils_examples.h"

// Function to create a memory provider which allocates memory from the specified NUMA node
int createMemoryProvider(umf_memory_provider_handle_t *hProvider,
                         umf_const_memspace_handle_t hMemspace) {
    int ret = 0;
    umf_result_t result;
    umf_mempolicy_handle_t hPolicy = NULL;
    if (hMemspace == NULL) {
        fprintf(stderr, "Memspace is NULL - do you have HMAT enabled?\n");
        return 1;
    }
    // Create a mempolicy - mempolicy defines how we want to use memory from memspace.
    // In this example, we want to bind memory to the best node in the memspace,
    // for the thread that allocates memory.
    result = umfMempolicyCreate(UMF_MEMPOLICY_BIND, &hPolicy);
    if (result != UMF_RESULT_SUCCESS) {
        ret = -1;
        fprintf(stderr, "umfMempolicyCreate failed.\n");
        goto error_mempolicy;
    }

    // Create a memory provider using the memory space and memory policy
    result = umfMemoryProviderCreateFromMemspace(hMemspace, hPolicy, hProvider);
    if (result != UMF_RESULT_SUCCESS) {
        ret = -1;
        fprintf(stderr, "umfMemoryProviderCreateFromMemspace failed.\n");
        goto error_provider;
    }

    // After creating the memory provider, we can destroy the mempolicy
error_provider:
    umfMempolicyDestroy(hPolicy);
error_mempolicy:
    return ret;
}

int main(void) {
    umf_memory_provider_handle_t hProvider = NULL;
    umf_result_t ret;
    void *ptr = NULL;
    size_t size = 1024;
    size_t alignment = 64;

    // Check if NUMA is available
    if (numa_available() < 0) {
        fprintf(stderr, "NUMA is not available on this system.\n");
        return TEST_SKIP_ERROR_CODE;
    }

    // Create the memory provider that allocates memory from the highest bandwidth numa nodes
    ret = createMemoryProvider(&hProvider, umfMemspaceHighestBandwidthGet());
    if (ret != UMF_RESULT_SUCCESS) {
        return ret == 1 ? TEST_SKIP_ERROR_CODE : -1;
    }

    // Allocate memory from the memory provider
    ret = umfMemoryProviderAlloc(hProvider, size, alignment, &ptr);
    if (ret != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "umfMemoryProviderAlloc failed.\n");
        umfMemoryProviderDestroy(hProvider);
        return -1;
    }

    // Use the allocated memory (ptr) here
    memset(ptr, 1, size);

    // Lets check the NUMA node of the allocated memory
    int nodeId;
    int retm = get_mempolicy(&nodeId, NULL, 0, ptr, MPOL_F_ADDR | MPOL_F_NODE);
    if (retm != 0) {
        fprintf(stderr, "get_mempolicy failed.\n");
        umfMemoryProviderFree(hProvider, ptr, size);
        umfMemoryProviderDestroy(hProvider);
        return -1;
    }

    printf("Allocated memory at %p from the highest bandwidth node: %d\n", ptr,
           nodeId);

    // Free the allocated memory
    umfMemoryProviderFree(hProvider, ptr, size);

    umfMemoryProviderDestroy(hProvider);

    // Lets now allocate memory from the lowest latency node
    ret = createMemoryProvider(&hProvider, umfMemspaceLowestLatencyGet());
    if (ret != UMF_RESULT_SUCCESS) {
        return -1;
    }

    ret = umfMemoryProviderAlloc(hProvider, size, alignment, &ptr);

    if (ret != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "umfMemoryProviderAlloc failed.\n");
        umfMemoryProviderDestroy(hProvider);
        return -1;
    }

    memset(ptr, 1, size);

    retm = get_mempolicy(&nodeId, NULL, 0, ptr, MPOL_F_ADDR | MPOL_F_NODE);
    if (retm != 0) {
        fprintf(stderr, "get_mempolicy failed.\n");
        umfMemoryProviderFree(hProvider, ptr, size);
        umfMemoryProviderDestroy(hProvider);
        return -1;
    }
    printf("Allocated memory at %p from the lowest latency node: %d\n", ptr,
           nodeId);

    // Free the allocated memory
    umfMemoryProviderFree(hProvider, ptr, size);

    umfMemoryProviderDestroy(hProvider);

    return 0;
}
