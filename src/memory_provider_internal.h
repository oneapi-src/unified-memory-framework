/*
 *
 * Copyright (C) 2023-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_MEMORY_PROVIDER_INTERNAL_H
#define UMF_MEMORY_PROVIDER_INTERNAL_H 1

#include <stdbool.h>

#include <umf/memory_provider.h>

#include "ctl/ctl.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct umf_memory_provider_t {
    void *provider_priv;
    // ops should be the last due to possible change size in the future
    umf_memory_provider_ops_t ops;
} umf_memory_provider_t;

void *umfMemoryProviderGetPriv(umf_memory_provider_handle_t hProvider);
umf_memory_provider_handle_t *umfGetLastFailedMemoryProviderPtr(void);

extern umf_ctl_node_t CTL_NODE(provider)[];
extern umf_ctl_node_t CTL_NODE(pool)[];

#ifdef __cplusplus
}
#endif

#endif /* UMF_MEMORY_PROVIDER_INTERNAL_H */
