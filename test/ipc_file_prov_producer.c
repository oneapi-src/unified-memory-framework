/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>

#include <umf/providers/provider_file_memory.h>

#include "ipc_common.h"
#include "ipc_os_prov_common.h"

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <port> <file_name>\n", argv[0]);
        return -1;
    }

    int port = atoi(argv[1]);
    char *file_name = argv[2];

    umf_file_memory_provider_params_t file_params;

    file_params = umfFileMemoryProviderParamsDefault(file_name);
    file_params.visibility = UMF_MEM_MAP_SHARED;

    return run_producer(port, umfFileMemoryProviderOps(), &file_params, memcopy,
                        NULL);
}
