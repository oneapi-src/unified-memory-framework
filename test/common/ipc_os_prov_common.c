/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <string.h>

#include "ipc_os_prov_common.h"

void memcopy(void *dst, const void *src, size_t size, void *context) {
    (void)context;
    memcpy(dst, src, size);
}
