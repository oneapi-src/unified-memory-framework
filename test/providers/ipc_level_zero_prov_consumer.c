/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>

#include <umf/pools/pool_disjoint.h>
#include <umf/providers/provider_level_zero.h>

#include "ipc_common.h"
#include "ipc_level_zero_prov_common.h"
#include "level_zero_helpers.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        return -1;
    }

    int port = atoi(argv[1]);

    level_zero_memory_provider_params_t l0_params =
        create_level_zero_prov_params(UMF_MEMORY_TYPE_DEVICE);

    umf_disjoint_pool_params_handle_t pool_params = NULL;

    umf_result_t umf_result = umfDisjointPoolParamsCreate(&pool_params);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to create pool params!\n");
        return -1;
    }

    int ret = run_consumer(port, umfDisjointPoolOps(), pool_params,
                           umfLevelZeroMemoryProviderOps(), &l0_params, memcopy,
                           &l0_params);

    umfDisjointPoolParamsDestroy(pool_params);

    return ret;
}
