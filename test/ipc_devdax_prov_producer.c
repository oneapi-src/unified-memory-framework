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
    if (argc < 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        return -1;
    }

    int port = atoi(argv[1]);

    umf_devdax_memory_provider_params_t devdax_params =
        umfDevDaxMemoryProviderParamsDefault(UMF_TESTS_DEVDAX_PATH,
                                             UMF_TESTS_DEVDAX_SIZE);

    return run_producer(port, umfDevDaxMemoryProviderOps(), &devdax_params,
                        memcopy, NULL);
}
