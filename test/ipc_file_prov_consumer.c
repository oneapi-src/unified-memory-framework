/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <umf/providers/provider_file_memory.h>

#include "ipc_common.h"
#include "ipc_os_prov_common.h"

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <port> <file_name>\n", argv[0]);
        return -1;
    }

    int ret = 0;
    int port = atoi(argv[1]);
    char *file_name = argv[2];

    umf_file_memory_provider_params_handle_t file_params = NULL;
    umf_result_t umf_result =
        umfFileMemoryProviderParamsCreate(&file_params, file_name);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(
            stderr,
            "[consumer] ERROR: creating File Memory Provider params failed\n");
        return -1;
    }

    umf_result = umfFileMemoryProviderParamsSetVisibility(file_params,
                                                          UMF_MEM_MAP_SHARED);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "[consumer] ERROR: setting File Memory Provider "
                        "visibility failed\n");
        ret = -1;
        goto destroy_provider_params;
    }

    void *pool_params = NULL;

    ret = run_consumer(port, umfScalablePoolOps(), pool_params,
                       umfFileMemoryProviderOps(), file_params, memcopy, NULL);

destroy_provider_params:
    umfFileMemoryProviderParamsDestroy(file_params);

    return ret;
}
