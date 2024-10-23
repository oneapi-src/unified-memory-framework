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
        fprintf(stderr, "usage: %s <port> <file_name> <fsdax>\n", argv[0]);
        fprintf(stderr, "       <fsdax> should be \"FSDAX\" or \"fsdax\" if "
                        "<file_name> is located on FSDAX \n");
        return -1;
    }

    int port = atoi(argv[1]);
    char *file_name = argv[2];
    bool is_fsdax = false;

    if (argc >= 4) {
        if (strncasecmp(argv[3], "FSDAX", strlen("FSDAX")) == 0) {
            is_fsdax = true;
        }
    }

    umf_file_memory_provider_params_t file_params;

    file_params = umfFileMemoryProviderParamsDefault(file_name);
    if (is_fsdax) {
        file_params.visibility = UMF_MEM_MAP_SYNC;
    } else {
        file_params.visibility = UMF_MEM_MAP_SHARED;
    }

    void *pool_params = NULL;

    return run_consumer(port, umfScalablePoolOps(), pool_params,
                        umfFileMemoryProviderOps(), &file_params, memcopy,
                        NULL);
}
