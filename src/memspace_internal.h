/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_MEMSPACE_INTERNAL_H
#define UMF_MEMSPACE_INTERNAL_H 1

#include <umf/memspace.h>

#include "base_alloc.h"
#include "base_alloc_linear.h"
#include "memory_target.h"

#ifdef __cplusplus
extern "C" {
#endif

struct umf_memspace_t {
    size_t size;
    umf_memory_target_handle_t *nodes;

    // own local linear base allocator
    umf_ba_linear_pool_t *linear_allocator;
};

///
/// \brief Destroys memspace
/// \param hMemspace handle to memspace
///
void umfMemspaceDestroy(umf_memspace_handle_t hMemspace);

#ifdef __cplusplus
}
#endif

#endif /* UMF_MEMSPACE_INTERNAL_H */
