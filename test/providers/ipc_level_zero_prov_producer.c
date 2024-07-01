/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>

#include <umf/providers/provider_level_zero.h>

#include "ipc_common.h"
#include "ipc_level_zero_prov_common.h"
#include "level_zero_helpers.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <port> [shm_name]\n", argv[0]);
        return -1;
    }

    int port = atoi(argv[1]);

    level_zero_memory_provider_params_t l0_params =
        create_level_zero_prov_params(UMF_MEMORY_TYPE_DEVICE);

    return run_producer(port, umfLevelZeroMemoryProviderOps(), &l0_params,
                        memcopy, &l0_params);
}
