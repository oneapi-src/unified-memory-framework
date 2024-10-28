/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>

#include <umf/pools/pool_disjoint.h>
#include <umf/providers/provider_cuda.h>

#include "cuda_helpers.h"
#include "ipc_common.h"
#include "ipc_cuda_prov_common.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        return -1;
    }

    int port = atoi(argv[1]);

    cuda_memory_provider_params_t cu_params =
        create_cuda_prov_params(UMF_MEMORY_TYPE_DEVICE);

    umf_disjoint_pool_params_t pool_params = umfDisjointPoolParamsDefault();

    return run_producer(port, umfDisjointPoolOps(), &pool_params,
                        umfCUDAMemoryProviderOps(), &cu_params, memcopy,
                        &cu_params);
}
