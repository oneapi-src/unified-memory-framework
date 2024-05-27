/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_MEMPOLICY_H
#define UMF_MEMPOLICY_H 1

#include <umf/base.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct umf_mempolicy_t *umf_mempolicy_handle_t;
typedef const struct umf_mempolicy_t *umf_const_mempolicy_handle_t;

typedef enum umf_mempolicy_membind_t {
    /// Interleave memory from all memory in memspace
    UMF_MEMPOLICY_INTERLEAVE,
    /// Bind memory to namespace
    UMF_MEMPOLICY_BIND,
    /// Prefer memory from namespace but fallback to other memory if not available
    UMF_MEMPOLICY_PREFERRED
} umf_mempolicy_membind_t;

///
/// @brief Creates a new memory policy
/// @param bind memory binding policy
/// @param hPolicy [out] handle to the newly created memory policy
/// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
///
umf_result_t umfMempolicyCreate(umf_mempolicy_membind_t bind,
                                umf_mempolicy_handle_t *hPolicy);

///
/// @brief Destroys memory policy
/// @param hPolicy handle to memory policy
/// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
///
umf_result_t umfMempolicyDestroy(umf_mempolicy_handle_t hPolicy);

///
/// @brief Sets custom part size for interleaved memory policy - by default it's interleaved by pages
/// @param hPolicy handle to memory policy
/// @param partSize size of the part or zero to use default part size (page size)
/// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
///
umf_result_t umfMempolicySetInterleavePartSize(umf_mempolicy_handle_t hPolicy,
                                               size_t partSize);
#ifdef __cplusplus
}
#endif

#endif /* UMF_MEMPOLICY_H */
