/*
 * Copyright (C) 2024-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>

#include <umf/providers/provider_cuda.h>

#include "cuda_helpers.h"
#include "ipc_cuda_prov_common.h"

void memcopy(void *dst, const void *src, size_t size, void *context) {
    cuda_copy_ctx_t *cu_params = (cuda_copy_ctx_t *)context;
    int ret = cuda_copy(cu_params->context, cu_params->device, dst, (void *)src,
                        size);
    if (ret != 0) {
        fprintf(stderr, "cuda_copy failed with error %d\n", ret);
    }
}
