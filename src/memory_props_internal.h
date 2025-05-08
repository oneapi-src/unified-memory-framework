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
#include <umf/memory_props.h>

#include "ze_api.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct umf_memory_properties_t {
    umf_memory_pool_handle_t pool;
    uint64_t id;

    // TODO
    bool gpu_properties_initialized;
    union {
        ze_memory_allocation_properties_t ze_properties;
    } gpu;
} umf_memory_properties_t;

#ifdef __cplusplus
}
#endif

#endif // UMF_MEMORY_PROPS_INTERNAL_H
