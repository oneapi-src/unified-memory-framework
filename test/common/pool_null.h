// Copyright (C) 2023-2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#ifndef UMF_TEST_NULL_POOL_H
#define UMF_TEST_NULL_POOL_H

#include <umf/memory_pool.h>

#if defined(__cplusplus)
extern "C" {
#endif

extern umf_memory_pool_ops_t UMF_NULL_POOL_OPS;

#if defined(__cplusplus)
}
#endif

#endif // UMF_TEST_NULL_POOL_H
