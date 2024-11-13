/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_JEMALLOC_MEMORY_POOL_H
#define UMF_JEMALLOC_MEMORY_POOL_H 1

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <umf/memory_pool_ops.h>

struct umf_jemalloc_pool_params_t;

/// @brief handle to the parameters of the jemalloc pool.
typedef struct umf_jemalloc_pool_params_t *umf_jemalloc_pool_params_handle_t;

/// @brief  Create a struct to store parameters of jemalloc pool.
/// @param  hParams [out] handle to the newly created parameters struct.
/// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
umf_result_t
umfJemallocPoolParamsCreate(umf_jemalloc_pool_params_handle_t *hParams);

/// @brief  Destroy parameters struct.
/// @param  hParams handle to the parameters of the jemalloc pool.
/// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
umf_result_t
umfJemallocPoolParamsDestroy(umf_jemalloc_pool_params_handle_t hParams);

/// @brief  Set if \p umfMemoryProviderFree() should never be called.
/// @param  hParams handle to the parameters of the jemalloc pool.
/// @param  keepAllMemory \p true if the jemalloc pool should not call
/// \p umfMemoryProviderFree, \p false otherwise.
/// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
umf_result_t
umfJemallocPoolParamsSetKeepAllMemory(umf_jemalloc_pool_params_handle_t hParams,
                                      bool keepAllMemory);

umf_memory_pool_ops_t *umfJemallocPoolOps(void);

#ifdef __cplusplus
}
#endif

#endif /* UMF_JEMALLOC_MEMORY_POOL_H */
