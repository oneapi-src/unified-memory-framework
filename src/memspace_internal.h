/*
 *
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_MEMSPACE_INTERNAL_H
#define UMF_MEMSPACE_INTERNAL_H 1

#include <umf/memspace.h>

#include "base_alloc.h"
#include "memory_target.h"

#ifdef __cplusplus
extern "C" {
#endif

struct umf_memspace_t {
    size_t size;
    umf_memory_target_handle_t *nodes;
};

///
/// \brief Clones memspace
///
enum umf_result_t umfMemspaceClone(umf_memspace_handle_t hMemspace,
                                   umf_memspace_handle_t *outHandle);

typedef umf_result_t (*umfGetPropertyFn)(umf_memory_target_handle_t,
                                         uint64_t *);

///
/// \brief Sorts memspace by getProperty() in descending order
///
enum umf_result_t umfMemspaceSortDesc(umf_memspace_handle_t hMemspace,
                                      umfGetPropertyFn getProperty);

///
/// \brief Destroys memspace
/// \param hMemspace handle to memspace
///
void umfMemspaceDestroy(umf_memspace_handle_t hMemspace);

void umfMemspaceHostAllDestroy(void);
void umfMemspaceHighestCapacityDestroy(void);

#ifdef __cplusplus
}
#endif

#endif /* UMF_MEMSPACE_INTERNAL_H */
