/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef UMF_TEST_IPC_LEVEL_ZERO_PROV_COMMON_H
#define UMF_TEST_IPC_LEVEL_ZERO_PROV_COMMON_H

#include <stddef.h>

void memcopy(void *dst, const void *src, size_t size, void *context);

#endif // UMF_TEST_IPC_LEVEL_ZERO_PROV_COMMON_H
