/*
 *
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_MEMORY_PROPS_INTERNAL_H
#define UMF_MEMORY_PROPS_INTERNAL_H 1

#include <stdbool.h>

#include <umf/base.h>
#include <umf/memory_pool.h>
#include <umf/memory_props.h>
#include <umf/memory_provider.h>

#if UMF_BUILD_LEVEL_ZERO_PROVIDER
#include "ze_api.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct umf_memory_properties_t {
    // TODO move to alloc_info_t w/o gpu_props
    void *ptr;
    umf_memory_pool_handle_t pool;
    umf_memory_provider_handle_t provider;
    uint64_t id;
    void *base;
    size_t base_size;

    // TODO
    bool gpu_properties_initialized;
    union {
#if UMF_BUILD_LEVEL_ZERO_PROVIDER
        ze_memory_allocation_properties_t ze_properties;
#endif
        int unused; // in case of no GPU support
    } gpu;
} umf_memory_properties_t;

#ifdef __cplusplus
}
#endif

#endif // UMF_MEMORY_PROPS_INTERNAL_H
