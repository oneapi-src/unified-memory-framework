/*
 *
 * Copyright (C) 2023-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_MEMTARGET_NUMA_H
#define UMF_MEMTARGET_NUMA_H 1

#include <umf.h>
#include <umf/memspace.h>

#include "../memtarget_internal.h"
#include "../memtarget_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

struct umf_numa_memtarget_config_t {
    size_t physical_id;
};

extern struct umf_memtarget_ops_t UMF_MEMTARGET_NUMA_OPS;

#ifdef __cplusplus
}
#endif

#endif /* UMF_MEMTARGET_NUMA_H */
