/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "ipc_level_zero_prov_common.h"
#include "utils_level_zero.h"

#include <umf/providers/provider_level_zero.h>

#include <stdio.h>

void memcopy(void *dst, const void *src, size_t size, void *context) {
    level_zero_copy_ctx_t *l0_params = (level_zero_copy_ctx_t *)context;
    int ret = utils_ze_level_zero_copy(l0_params->context, l0_params->device,
                                       dst, src, size);
    if (ret != 0) {
        fprintf(stderr, "level_zero_copy failed with error %d\n", ret);
    }
}
