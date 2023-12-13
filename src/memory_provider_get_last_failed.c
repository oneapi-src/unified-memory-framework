/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "common.h"
#include "memory_provider_internal.h"

static __TLS umf_memory_provider_handle_t lastFailedProvider = NULL;

umf_memory_provider_handle_t *umfGetLastFailedMemoryProviderPtr(void) {
    return &lastFailedProvider;
}
