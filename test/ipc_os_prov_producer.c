/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>

#include <umf/providers/provider_os_memory.h>

#include "ipc_common.h"
#include "ipc_os_prov_common.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <port> [shm_name]\n", argv[0]);
        return -1;
    }

    int ret = 0;
    int port = atoi(argv[1]);

    umf_os_memory_provider_params_handle_t os_params = NULL;

    umf_result_t umf_result = umfOsMemoryProviderParamsCreate(&os_params);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(
            stderr,
            "[producer] ERROR: creating OS memory provider params failed\n");
        return -1;
    }

    umf_result =
        umfOsMemoryProviderParamsSetVisibility(os_params, UMF_MEM_MAP_SHARED);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "[producer] ERROR: setting visibility mode failed\n");
        ret = -1;
        goto destroy_provider_params;
    }

    if (argc >= 3) {
        umf_result = umfOsMemoryProviderParamsSetShmName(os_params, argv[2]);
        if (umf_result != UMF_RESULT_SUCCESS) {
            fprintf(stderr,
                    "[producer] ERROR: setting shared memory name failed\n");
            ret = -1;
            goto destroy_provider_params;
        }
    }

    void *pool_params = NULL;

    ret = run_producer(port, umfScalablePoolOps(), pool_params,
                       umfOsMemoryProviderOps(), os_params, memcopy, NULL);

destroy_provider_params:
    umfOsMemoryProviderParamsDestroy(os_params);

    return ret;
}
