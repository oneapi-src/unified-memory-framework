/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_MEMORY_TARGET_NUMA_H
#define UMF_MEMORY_TARGET_NUMA_H 1

#include <umf.h>
#include <umf/memspace.h>

#include "../memory_target.h"
#include "../memory_target_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

struct umf_numa_memory_target_config_t {
    size_t id;
};

extern struct umf_memory_target_ops_t UMF_MEMORY_TARGET_NUMA_OPS;

#ifdef __cplusplus
}
#endif

#endif /* UMF_MEMORY_TARGET_NUMA_H */
