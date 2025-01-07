/*
 * Copyright (C) 2024-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>

#include <umf/providers/provider_devdax_memory.h>

#include "ipc_common.h"
#include "ipc_os_prov_common.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        return -1;
    }

    int ret = 0;
    int port = atoi(argv[1]);

    char *path = getenv("UMF_TESTS_DEVDAX_PATH");
    if (path == NULL || path[0] == 0) {
        fprintf(stderr, "Test skipped, UMF_TESTS_DEVDAX_PATH is not set\n");
        return 0;
    }

    char *size = getenv("UMF_TESTS_DEVDAX_SIZE");
    if (size == NULL || size[0] == 0) {
        fprintf(stderr, "Test skipped, UMF_TESTS_DEVDAX_SIZE is not set\n");
        return 0;
    }

    umf_devdax_memory_provider_params_handle_t devdax_params = NULL;
    umf_result_t umf_result =
        umfDevDaxMemoryProviderParamsCreate(&devdax_params, path, atol(size));
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "[consumer] ERROR: creating DevDax Memory Provider "
                        "params failed\n");
        return -1;
    }

    void *pool_params = NULL;

    ret = run_consumer(port, umfScalablePoolOps(), pool_params,
                       umfDevDaxMemoryProviderOps(), devdax_params, memcopy,
                       NULL);

    umfDevDaxMemoryProviderParamsDestroy(devdax_params);

    return ret;
}
