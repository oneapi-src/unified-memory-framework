/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */
#define _GNU_SOURCE 1

#include <umf/base.h>
#include <umf/pools/pool_scalable.h>

#include <fcntl.h>
#include <linux/falloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// Define the size for address reservation
#define ADDRESS_RESERVATION ((size_t)16 * 1024 * 1024 * 1024)

// Macro to align a value up to the nearest multiple of align
#define ALIGN_UP(value, align) (((value) + (align)-1) & ~((align)-1))

// Struct to represent the file provider
typedef struct file_provider_t {
    void *ptr;        // Pointer to the reserved memory
    size_t poffset;   // Offset for the next allocation
    int fd;           // File descriptor for the backing file
    size_t foffset;   // Offset within the file for the next allocation
    size_t page_size; // System page size
} file_provider_t;

// Struct to represent the file parameters
typedef struct file_params_t {
    const char *filename; // Filename for the backing file
} file_params_t;

// Function to initialize the file provider
static umf_result_t file_init(void *params, void **provider) {
    file_provider_t *file_provider = NULL;

    if (params == NULL || provider == NULL) {
        fprintf(stderr, "Params or provider cannot be null\n");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    file_params_t *file_params = (file_params_t *)params;
    int page_size = 0;
    umf_result_t ret = UMF_RESULT_SUCCESS;

    // Allocate memory for the file provider
    file_provider = malloc(sizeof(*file_provider));
    if (!file_provider) {
        fprintf(stderr, "Failed to allocate memory for file provider\n");
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    // Open the file
    file_provider->fd = open(file_params->filename, O_RDWR | O_CREAT, 0666);
    if (file_provider->fd < 0) {
        perror("Failed to open file");
        ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto cleanup_malloc;
    }

    // Reserve address space for subsequent allocations.
    // This simplifies translation between addresses and offset in the file.
    file_provider->ptr = mmap(NULL, ADDRESS_RESERVATION, PROT_NONE,
                              MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (file_provider->ptr == MAP_FAILED) {
        perror("Failed to memory map anonymous memory");
        ret = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        goto cleanup_fd;
    }

    // Get the page size
    page_size = sysconf(_SC_PAGESIZE);
    if (page_size < 0) {
        perror("Failed to get system page size");
        ret = UMF_RESULT_ERROR_UNKNOWN;
        goto cleanup_mmap;
    }

    // Initialize the file provider fields
    file_provider->poffset = 0;
    file_provider->foffset = 0;
    file_provider->page_size = (size_t)page_size;
    *provider = file_provider;

    return UMF_RESULT_SUCCESS;

cleanup_mmap:
    munmap(file_provider->ptr, ADDRESS_RESERVATION);
cleanup_fd:
    close(file_provider->fd);
cleanup_malloc:
    free(file_provider);
    return ret;
}

// Function to deinitialize the file provider
static void file_deinit(void *provider) {
    file_provider_t *file_provider = (file_provider_t *)provider;
    munmap(file_provider->ptr, ADDRESS_RESERVATION);
    close(file_provider->fd);
    free(file_provider);
}

// Function to allocate memory from the file provider
static umf_result_t file_alloc(void *provider, size_t size, size_t alignment,
                               void **ptr) {
    if (provider == NULL || ptr == NULL) {
        fprintf(stderr, "Provider or ptr cannot be null\n");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    file_provider_t *file_provider = (file_provider_t *)provider;
    size_t page_size = file_provider->page_size;

    if (alignment && (alignment % page_size) && (page_size % alignment)) {
        fprintf(stderr,
                "Wrong alignment: %zu (not a multiple or a divider of the "
                "minimum page size (%zu))",
                alignment, page_size);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    size = ALIGN_UP(size, page_size);

    // calculate address for new allocation. All allocation are page aligned so
    // if alignment is bigger than page size we have to adjust the address
    uintptr_t ptr_offset =
        (uintptr_t)file_provider->ptr + file_provider->poffset;
    uintptr_t aligned_ptr =
        alignment > page_size ? ALIGN_UP(ptr_offset, alignment) : ptr_offset;

    size_t new_offset = aligned_ptr + size - (uintptr_t)file_provider->ptr;
    if (new_offset + size > ADDRESS_RESERVATION) {
        fprintf(stderr, "This example limits allocation up to 10GB\n");
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    // Ensure the file is large enough to hold the new allocation
    if (fallocate(file_provider->fd, 0, file_provider->foffset, size)) {
        perror("Fallocate failed");
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }
    // Map the file in place of the reservation
    void *ret = mmap((void *)aligned_ptr, size, PROT_READ | PROT_WRITE,
                     MAP_FIXED | MAP_PRIVATE, file_provider->fd,
                     file_provider->foffset);
    if (ret == MAP_FAILED) {
        perror("Memory map failed");
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    file_provider->poffset = new_offset;
    file_provider->foffset += size;
    *ptr = ret;
    return UMF_RESULT_SUCCESS;
}

// Function to free allocated memory from the file provider
static umf_result_t file_free(void *provider, void *ptr, size_t size) {
    if (provider == NULL || ptr == NULL) {
        fprintf(stderr, "Provider or ptr cannot be null\n");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    file_provider_t *file_provider = (file_provider_t *)provider;
    if (size == 0) {
        fprintf(stderr, "Size cannot be 0\n");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (ptr < file_provider->ptr ||
        (uintptr_t)ptr >=
            (uintptr_t)file_provider->ptr + file_provider->poffset) {
        fprintf(stderr, "Ptr is not within the provider's memory\n");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    size = ALIGN_UP(size, file_provider->page_size);

    // Replace allocation with a reservation to free memory
    void *ptr2 = mmap(ptr, size, PROT_NONE,
                      MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (ptr2 == MAP_FAILED) {
        perror("Failed to free memory");
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    // Free allocated blocks to the filesystem
    if (fallocate(file_provider->fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                  (uintptr_t)ptr - (uintptr_t)file_provider->ptr, size)) {
        perror("Fallocate failed");
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    return UMF_RESULT_SUCCESS;
}

// Function to get the name of the file provider
static const char *file_get_name(void *provider) {
    (void)provider; // Unused parameter
    return "File Provider";
}

// Function to get the last native error of the file provider
// This function is needed only if the provider returns UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC
static void file_get_last_native_error(void *provider, const char **ppMessage,
                                       int32_t *pError) {
    (void)provider; // Unused parameter
    *ppMessage = "";
    *pError = 0;
}

// Function to get the recommended page size of the file provider
static umf_result_t file_get_recommended_page_size(void *provider, size_t size,
                                                   size_t *pageSize) {
    (void)size; // Unused parameter
    if (provider == NULL || pageSize == NULL) {
        fprintf(stderr, "Provider or pageSize cannot be null\n");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    file_provider_t *file_provider = (file_provider_t *)provider;
    *pageSize = file_provider->page_size;
    return UMF_RESULT_SUCCESS;
}

// Function to get the minimum page size of the file provider
static umf_result_t file_get_min_page_size(void *provider, void *ptr,
                                           size_t *pageSize) {
    (void)ptr; // Unused parameter
    if (provider == NULL || pageSize == NULL) {
        fprintf(stderr, "Provider or pageSize cannot be null\n");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    file_provider_t *file_provider = (file_provider_t *)provider;
    *pageSize = file_provider->page_size;
    return UMF_RESULT_SUCCESS;
}

// File provider operations
static umf_memory_provider_ops_t file_ops = {
    .version = UMF_VERSION_CURRENT,
    .initialize = file_init,
    .finalize = file_deinit,
    .alloc = file_alloc,
    .get_name = file_get_name,
    .get_last_native_error = file_get_last_native_error,
    .get_recommended_page_size = file_get_recommended_page_size,
    .get_min_page_size = file_get_min_page_size,
    .ext.free = file_free,
};

// Main function
int main(void) {
    // A result object for storing UMF API result status
    umf_result_t res;
    umf_memory_provider_handle_t provider;
    file_params_t params;
    params.filename = "/tmp/file_provider_example";

    // Create a memory provider
    res = umfMemoryProviderCreate(&file_ops, &params, &provider);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to create a memory provider!\n");
        return -1;
    }
    printf("OS memory provider created at %p\n", (void *)provider);

    // Allocate memory from the memory provider
    size_t alloc_size = 5000;
    size_t alignment = 0;
    void *ptr_provider = NULL;

    res =
        umfMemoryProviderAlloc(provider, alloc_size, alignment, &ptr_provider);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "Failed to allocate memory from the memory provider!\n");
        goto memory_provider_destroy;
    }

    const char *strSource = "Allocated memory at";

    // Write to the allocated memory
    memset(ptr_provider, '\0', alloc_size);
    strncpy(ptr_provider, strSource, alloc_size);
    printf("%s %p with the memory provider at %p\n", (char *)ptr_provider,
           (void *)ptr_provider, (void *)provider);

    // Free the allocated memory
    res = umfMemoryProviderFree(provider, ptr_provider, alloc_size);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to free memory to the provider!\n");
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
        fprintf(stderr, "Failed to create a pool!\n");
        goto memory_provider_destroy;
    }
    printf("Scalable memory pool created at %p\n", (void *)pool);

    // Allocate some memory in the pool
    size_t num = 1;
    alloc_size = 128;

    char *ptr = umfPoolCalloc(pool, num, alloc_size);
    if (!ptr) {
        fprintf(stderr, "Failed to allocate memory in the pool!\n");
        goto memory_pool_destroy;
    }

    // Write a string to the allocated memory
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
        fprintf(stderr, "Failed to retrieve a memory provider for the pool!\n");
        goto memory_pool_destroy;
    }
    printf("Pool at %p has been allocated from the provider at %p\n",
           (void *)pool, (void *)check_provider);

    // Clean up
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
