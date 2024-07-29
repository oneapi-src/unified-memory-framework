/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#ifndef UMF_PROVIDER_CUDA_H
#define UMF_PROVIDER_CUDA_H

#include <umf/memory_provider_gpu.h>

#ifdef __cplusplus
extern "C" {
#endif

/// @brief CUDA Memory Provider settings struct
typedef struct cuda_memory_provider_params_t {
    void *cuda_context_handle;         ///< Handle to the CUDA context
    int cuda_device_handle;            ///< Handle to the CUDA device
    umf_usm_memory_type_t memory_type; ///< Allocation memory type
} cuda_memory_provider_params_t;

umf_memory_provider_ops_t *umfCUDAMemoryProviderOps(void);

#ifdef __cplusplus
}
#endif

#endif /* UMF_PROVIDER_CUDA_H */
