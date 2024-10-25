/*
 * Copyright (C) 2024 Intel Corporation
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
    if (argc < 2 || argc == 3) {
        fprintf(stderr, "usage: %s <port> [path_devdax] [size_devdax]\n",
                argv[0]);
        if (argc == 3) {
            fprintf(stderr, "error: both [path_devdax] and [size_devdax] have "
                            "to be provided, not only one of them\n");
        }

        return -1;
    }

    int port = atoi(argv[1]);
    char *path = NULL;
    char *size = "0";

    if (argc >= 4) {
        path = argv[2];
        size = argv[3];
    }

    umf_devdax_memory_provider_params_t devdax_params =
        umfDevDaxMemoryProviderParamsDefault(path, atol(size));

    void *pool_params = NULL;

    return run_consumer(port, umfScalablePoolOps(), pool_params,
                        umfDevDaxMemoryProviderOps(), &devdax_params, memcopy,
                        NULL);
}
