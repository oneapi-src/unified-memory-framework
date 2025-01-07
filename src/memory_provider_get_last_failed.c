/*
 *
 * Copyright (C) 2023-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "memory_provider_internal.h"
#include "utils_common.h"

static __TLS umf_memory_provider_handle_t lastFailedProvider = NULL;

umf_memory_provider_handle_t *umfGetLastFailedMemoryProviderPtr(void) {
    return &lastFailedProvider;
}
