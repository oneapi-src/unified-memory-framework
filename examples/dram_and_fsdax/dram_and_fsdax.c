/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <umf/memory_provider.h>
#include <umf/providers/provider_file_memory.h>
#include <umf/providers/provider_os_memory.h>

#include <umf/memory_pool.h>
#include <umf/pools/pool_jemalloc.h>

static umf_memory_pool_handle_t create_dram_pool(void) {
    umf_memory_provider_handle_t provider_dram = NULL;
    umf_memory_pool_handle_t pool_dram;
    umf_result_t umf_result;

    umf_os_memory_provider_params_t params_dram =
        umfOsMemoryProviderParamsDefault();

    umf_result = umfMemoryProviderCreate(umfOsMemoryProviderOps(), &params_dram,
                                         &provider_dram);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Creation of the OS memory provider failed");
        return NULL;
    }

    // Create a DRAM memory pool
    umf_result = umfPoolCreate(umfJemallocPoolOps(), provider_dram, NULL,
                               UMF_POOL_CREATE_FLAG_OWN_PROVIDER, &pool_dram);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to create a DRAM memory pool!\n");
        umfMemoryProviderDestroy(provider_dram);
        return NULL;
    }

    return pool_dram;
}

static umf_memory_pool_handle_t create_fsdax_pool(const char *path) {
    umf_memory_provider_handle_t provider_fsdax = NULL;
    umf_memory_pool_handle_t pool_fsdax;
    umf_result_t umf_result;

    umf_file_memory_provider_params_t params_fsdax =
        umfFileMemoryProviderParamsDefault(path);
    // FSDAX requires mapping the UMF_MEM_MAP_SYNC flag
    params_fsdax.visibility = UMF_MEM_MAP_SYNC;

    umf_result = umfMemoryProviderCreate(umfFileMemoryProviderOps(),
                                         &params_fsdax, &provider_fsdax);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to create the FSDAX file provider");
        return NULL;
    }

    // Create an FSDAX memory pool
    //
    // The file memory provider does not support the free operation
    // (`umfMemoryProviderFree()` always returns `UMF_RESULT_ERROR_NOT_SUPPORTED`),
    // so it should be used with a pool manager that will take over
    // the managing of the provided memory - for example the jemalloc pool
    // with the `disable_provider_free` parameter set to true.
    umf_jemalloc_pool_params_t pool_params;
    pool_params.disable_provider_free = true;

    // Create an FSDAX memory pool
    umf_result =
        umfPoolCreate(umfJemallocPoolOps(), provider_fsdax, &pool_params,
                      UMF_POOL_CREATE_FLAG_OWN_PROVIDER, &pool_fsdax);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to create an FSDAX memory pool!\n");
        umfMemoryProviderDestroy(provider_fsdax);
        return NULL;
    }

    return pool_fsdax;
}

int main(void) {
    int ret = -1;

    // This example requires:
    // - the FSDAX device to be mounted in the OS (e.g. /mnt/pmem1) and
    // - the UMF_TESTS_FSDAX_PATH environment variable to contain
    //   a path to a file on this FSDAX device.
    char *path = getenv("UMF_TESTS_FSDAX_PATH");
    if (path == NULL || path[0] == 0) {
        fprintf(
            stderr,
            "Warning: UMF_TESTS_FSDAX_PATH is not set, skipping testing ...\n");
        return 0;
    }

    umf_memory_pool_handle_t dram_pool = create_dram_pool();
    if (dram_pool == NULL) {
        fprintf(stderr, "Failed to create a DRAM memory pool!\n");
        return -1;
    }

    fprintf(stderr, "Created a DRAM memory pool\n");

    umf_memory_pool_handle_t fsdax_pool = create_fsdax_pool(path);
    if (fsdax_pool == NULL) {
        fprintf(stderr, "Failed to create an FSDAX memory pool!\n");
        goto err_destroy_dram_pool;
    }

    fprintf(stderr, "Created an FSDAX memory pool\n");

    size_t size = 2 * 1024 * 1024; // == 2 MB

    // Allocate from the DRAM memory pool
    char *dram_buf = umfPoolCalloc(dram_pool, 1, size);
    if (dram_buf == NULL) {
        fprintf(stderr,
                "Failed to allocate memory from the DRAM memory pool!\n");
        goto err_destroy_pools;
    }

    fprintf(stderr, "Allocated memory from the DRAM memory pool\n");

    // Allocate from the FSDAX memory pool
    char *fsdax_buf = umfPoolCalloc(fsdax_pool, 1, size);
    if (fsdax_buf == NULL) {
        fprintf(stderr,
                "Failed to allocate memory from the FSDAX memory pool!\n");
        goto err_free_dram;
    }

    fprintf(stderr, "Allocated memory from the FSDAX memory pool\n");

    // Use the allocation from DRAM
    dram_buf[0] = '.';

    // Use the allocation from FSDAX
    fsdax_buf[0] = '.';

    // success
    ret = 0;

    // The file memory provider does not support the free() operation,
    // so we do not need to call: umfPoolFree(fsdax_pool, fsdax_buf);

err_free_dram:
    fprintf(stderr, "Freeing the allocation from the DRAM memory pool ...\n");
    umfPoolFree(dram_pool, dram_buf);

err_destroy_pools:
    fprintf(stderr, "Destroying the FSDAX memory pool ...\n");
    umfPoolDestroy(fsdax_pool);

err_destroy_dram_pool:
    fprintf(stderr, "Destroying the DRAM memory pool ...\n");
    umfPoolDestroy(dram_pool);

    return ret;
}
