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

// Function to create a memory provider which allocates memory from the specified NUMA node
int createMemoryProvider(umf_memory_provider_handle_t *hProvider,
                         unsigned numa) {
    int ret = 0;
    umf_result_t result;
    umf_memspace_handle_t hMemspace = NULL;
    umf_mempolicy_handle_t hPolicy = NULL;

    // Create a memspace - memspace is a list of memory sources.
    // In this example, we create a memspace that contains single numa node;
    result = umfMemspaceCreateFromNumaArray(&numa, 1, &hMemspace);
    if (result != UMF_RESULT_SUCCESS) {
        ret = -1;
        fprintf(stderr, "umfMemspaceCreateFromNumaArray failed.\n");
        goto error_memspace;
    }

    // Create a mempolicy - mempolicy defines how we want to use memory from memspace.
    // In this example, we want to bind memory to the specified numa node.
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

    // After creating the memory provider, we can destroy the memspace and mempolicy
error_provider:
    umfMempolicyDestroy(hPolicy);
error_mempolicy:
    umfMemspaceDestroy(hMemspace);
error_memspace:
    return ret;
}

int main(void) {
    umf_memory_provider_handle_t hProvider = NULL;
    umf_result_t ret;

    // Check if NUMA is available
    if (numa_available() < 0) {
        fprintf(stderr, "NUMA is not available on this system.\n");
        return -1;
    }

    // Create the memory provider that allocates memory from the specified NUMA node
    // In this example, we allocate memory from the NUMA node 0
    ret = createMemoryProvider(&hProvider, 0);
    if (ret != UMF_RESULT_SUCCESS) {
        return -1;
    }

    // Allocate memory from the memory provider
    void *ptr = NULL;
    size_t size = 1024;
    size_t alignment = 64;

    ret = umfMemoryProviderAlloc(hProvider, size, alignment, &ptr);
    if (ret != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "umfMemoryProviderAlloc failed.\n");
        goto error_alloc;
    }

    // Use the allocated memory (ptr) here
    memset(ptr, 1, size);

    // Lets check the NUMA node of the allocated memory
    int nodeId;
    int retm = get_mempolicy(&nodeId, NULL, 0, ptr, MPOL_F_ADDR | MPOL_F_NODE);
    if (retm != 0) {
        fprintf(stderr, "get_mempolicy failed.\n");
        goto error_alloc;
    }
    printf("Allocated memory at %p from numa_node %d\n", ptr, nodeId);
    // Free the allocated memory
    umfMemoryProviderFree(hProvider, ptr, size);
error_alloc:
    umfMemoryProviderDestroy(hProvider);

    return ret == UMF_RESULT_SUCCESS ? 0 : 1;
}
