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

#include "examples_utils.h"

// Function to create a memory provider which allocates memory from the specified NUMA node
// by using umfMemspaceCreateFromNumaArray
int createMemoryProviderFromArray(umf_memory_provider_handle_t *hProvider,
                                  unsigned numa) {
    int ret = 0;
    umf_result_t result;
    umf_memspace_handle_t hMemspace = NULL;
    umf_mempolicy_handle_t hPolicy = NULL;

    // Create a memspace - memspace is a list of memory sources.
    // In this example, we create a memspace that contains single numa node;
    result = umfMemspaceCreateFromNumaArray(&numa, 1, &hMemspace);
    if (result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "umfMemspaceCreateFromNumaArray() failed.\n");
        return -1;
    }

    // Create a mempolicy - mempolicy defines how we want to use memory from memspace.
    // In this example, we want to bind memory to the specified numa node.
    result = umfMempolicyCreate(UMF_MEMPOLICY_BIND, &hPolicy);
    if (result != UMF_RESULT_SUCCESS) {
        ret = -1;
        fprintf(stderr, "umfMempolicyCreate failed().\n");
        goto error_memspace;
    }

    // Create a memory provider using the memory space and memory policy
    result = umfMemoryProviderCreateFromMemspace(hMemspace, hPolicy, hProvider);
    if (result != UMF_RESULT_SUCCESS) {
        ret = -1;
        fprintf(stderr, "umfMemoryProviderCreateFromMemspace failed().\n");
        goto error_mempolicy;
    }

    // After creating the memory provider, we can destroy the memspace and mempolicy
error_mempolicy:
    umfMempolicyDestroy(hPolicy);
error_memspace:
    umfMemspaceDestroy(hMemspace);
    return ret;
}

// Function to create a memory provider which allocates memory from the specified NUMA node
// by using filter function.
int createMemoryProviderByFilter(umf_memory_provider_handle_t *hProvider,
                                 unsigned numa) {
    int ret = 0;
    umf_result_t result;
    umf_memspace_handle_t hMemspace = NULL;
    umf_mempolicy_handle_t hPolicy = NULL;

    umf_const_memspace_handle_t hostAll = umfMemspaceHostAllGet();
    if (!hostAll) {
        fprintf(stderr, "umfMemspaceHostAllGet() failed\n");
        return -1;
    }

    // umfMemspaceHostAllGet() return immutable memspace, so we need to create a mutable copy
    result = umfMemspaceClone(hostAll, &hMemspace);
    if (result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "umfMempolicyClone() failed.\n");
        return -1;
    }

    // Filter the memspace to contain only the specified numa node
    result = umfMemspaceFilterById(hMemspace, &numa, 1);
    if (result != UMF_RESULT_SUCCESS) {
        ret = -1;
        fprintf(stderr, "umfMemspaceFilterById() failed.\n");
        goto error_memspace;
    }

    // Create a mempolicy - mempolicy defines how we want to use memory from memspace.
    // In this example, we want to bind memory to the specified numa node.
    result = umfMempolicyCreate(UMF_MEMPOLICY_BIND, &hPolicy);
    if (result != UMF_RESULT_SUCCESS) {
        ret = -1;
        fprintf(stderr, "umfMempolicyCreate() failed.\n");
        goto error_memspace;
    }
    // Create a memory provider using the memory space and memory policy
    result = umfMemoryProviderCreateFromMemspace(hMemspace, hPolicy, hProvider);
    if (result != UMF_RESULT_SUCCESS) {
        ret = -1;
        fprintf(stderr, "umfMemoryProviderCreateFromMemspace() failed.\n");
        goto error_mempolicy;
    }

    // After creating the memory provider, we can destroy the memspace and mempolicy
error_mempolicy:
    umfMempolicyDestroy(hPolicy);
error_memspace:
    umfMemspaceDestroy(hMemspace);
    return ret;
}

int use_memory_provider(umf_memory_provider_handle_t hProvider) {
    // Allocate memory from the memory provider
    void *ptr = NULL;
    size_t size = 1024;
    size_t alignment = 64;

    umf_result_t ret = umfMemoryProviderAlloc(hProvider, size, alignment, &ptr);
    if (ret != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "umfMemoryProviderAlloc failed.\n");
        return 1;
    }

    // Use the allocated memory (ptr) here
    memset(ptr, 1, size);

    // Lets check the NUMA node of the allocated memory
    int nodeId;
    int retm = get_mempolicy(&nodeId, NULL, 0, ptr, MPOL_F_ADDR | MPOL_F_NODE);
    if (retm != 0) {
        umfMemoryProviderFree(hProvider, ptr, size);
        fprintf(stderr, "get_mempolicy failed.\n");
        return 1;
    }
    printf("Allocated memory at %p from numa_node %d\n", ptr, nodeId);
    // Free the allocated memory
    umfMemoryProviderFree(hProvider, ptr, size);

    return 0;
}

int main(void) {
    umf_memory_provider_handle_t hProvider = NULL;
    umf_result_t ret;

    // Check if NUMA is available
    if (numa_available() < 0) {
        fprintf(stderr, "NUMA is not available on this system.\n");
        return TEST_SKIP_ERROR_CODE;
    }

    // Create the memory provider that allocates memory from the specified NUMA node
    // In this example, we allocate memory from the NUMA node 0
    ret = createMemoryProviderFromArray(&hProvider, 0);
    if (ret != UMF_RESULT_SUCCESS) {
        return -1;
    }

    if (use_memory_provider(hProvider)) {
        goto error;
    }

    umfMemoryProviderDestroy(hProvider);

    // We can achieve the same result by using filter functions
    ret = createMemoryProviderByFilter(&hProvider, 0);
    if (ret != UMF_RESULT_SUCCESS) {
        return -1;
    }

    if (use_memory_provider(hProvider)) {
        goto error;
    }

    umfMemoryProviderDestroy(hProvider);
    return 0;
error:
    umfMemoryProviderDestroy(hProvider);

    return 1;
}
