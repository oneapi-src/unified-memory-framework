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

    int port = atoi(argv[1]);

    umf_os_memory_provider_params_t os_params;

    os_params = umfOsMemoryProviderParamsDefault();
    os_params.visibility = UMF_MEM_MAP_SHARED;
    if (argc >= 3) {
        os_params.shm_name = argv[2];
    }

    void *pool_params = NULL;

    return run_producer(port, umfScalablePoolOps(), pool_params,
                        umfOsMemoryProviderOps(), &os_params, memcopy, NULL);
}
