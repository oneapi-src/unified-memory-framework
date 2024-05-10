/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "umf/pools/pool_scalable.h"
#include "umf/providers/provider_os_memory.h"

#include <stdio.h>
#include <string.h>

int main(void) {
    // A result object for storing UMF API result status
    umf_result_t res;

    // Create an OS memory provider. It is used for allocating memory from
    // NUMA nodes visible to the operating system.
    // Allocations are made with mmap. The default values of params result
    // in an mmap call like this:
    // mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)
    umf_memory_provider_ops_t *provider_ops = umfOsMemoryProviderOps();
    umf_os_memory_provider_params_t params = umfOsMemoryProviderParamsDefault();
    umf_memory_provider_handle_t provider;

    res = umfMemoryProviderCreate(provider_ops, &params, &provider);
    if (res != UMF_RESULT_SUCCESS) {
        printf("Failed to create a memory provider!\n");
        return -1;
    }
    printf("OS memory provider created at %p\n", (void *)provider);

    // Allocate memory from memory provider
    size_t alloc_size = 5000;
    size_t alignment = 0;
    void *ptr_provider = NULL;

    res =
        umfMemoryProviderAlloc(provider, alloc_size, alignment, &ptr_provider);
    if (res != UMF_RESULT_SUCCESS) {
        printf("Failed to allocate memory from the memory provider!\n");
        goto memory_provider_destroy;
    }

    const char *strSource = "Allocated memory at";

    // Write to the allocated memory
    memset(ptr_provider, '\0', alloc_size);
    strncpy(ptr_provider, strSource, alloc_size);
    printf("%s %p with the memory provider at %p\n", (char *)ptr_provider,
           (void *)ptr_provider, (void *)provider);

    // Free allocated memory
    res = umfMemoryProviderFree(provider, ptr_provider, alloc_size);
    if (res != UMF_RESULT_SUCCESS) {
        printf("Failed to free memory to the provider!\n");
        goto memory_provider_destroy;
    }
    printf("Freed memory at %p\n", ptr_provider);

    // Create a memory pool
    umf_memory_pool_ops_t *pool_ops = umfScalablePoolOps();
    void *pool_params = NULL;
    umf_pool_create_flags_t flags = 0;
    umf_memory_pool_handle_t pool;

    res = umfPoolCreate(pool_ops, provider, pool_params, flags, &pool);
    if (res != UMF_RESULT_SUCCESS) {
        printf("Failed to create a pool!\n");
        goto memory_provider_destroy;
    }
    printf("Scalable memory pool created at %p\n", (void *)pool);

    // Allocate some memory in the pool
    size_t num = 1;
    alloc_size = 128;

    char *ptr = umfPoolCalloc(pool, num, alloc_size);
    if (!ptr) {
        printf("Failed to allocate memory in the pool!\n");
        goto memory_pool_destroy;
    }

    // Write a string to allocated memory
    strncpy(ptr, strSource, alloc_size);
    printf("%s %p\n", ptr, (void *)ptr);

    // Retrieve a memory pool from a pointer, available with memory tracking
    umf_memory_pool_handle_t check_pool = umfPoolByPtr(ptr);
    printf("Memory at %p has been allocated from the pool at %p\n", (void *)ptr,
           (void *)check_pool);

    // Retrieve a memory provider from a pool
    umf_memory_provider_handle_t check_provider;
    res = umfPoolGetMemoryProvider(pool, &check_provider);
    if (res != UMF_RESULT_SUCCESS) {
        printf("Failed to retrieve a memory provider for the pool!\n");
        goto memory_pool_destroy;
    }
    printf("Pool at %p has been allocated from the provider at %p\n",
           (void *)pool, (void *)check_provider);

    // Clean up.
    umfFree(ptr);
    umfPoolDestroy(pool);
    umfMemoryProviderDestroy(provider);
    return 0;

memory_pool_destroy:
    umfPoolDestroy(pool);
memory_provider_destroy:
    umfMemoryProviderDestroy(provider);
    return -1;
}
