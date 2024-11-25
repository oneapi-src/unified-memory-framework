/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef UMF_TEST_IPC_LEVEL_ZERO_PROV_COMMON_H
#define UMF_TEST_IPC_LEVEL_ZERO_PROV_COMMON_H

#include <stddef.h>

#include "ze_api.h"

typedef struct level_zero_copy_ctx_t {
    ze_context_handle_t context;
    ze_device_handle_t device;
} level_zero_copy_ctx_t;

void memcopy(void *dst, const void *src, size_t size, void *context);

#endif // UMF_TEST_IPC_LEVEL_ZERO_PROV_COMMON_H
