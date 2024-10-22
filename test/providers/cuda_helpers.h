/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef TEST_COMMON_CUDA_HELPERS_HPP
#define TEST_COMMON_CUDA_HELPERS_HPP

#include <umf/providers/provider_cuda.h>

#include "cuda.h"

#ifdef __cplusplus
extern "C" {
#endif

int destroy_context(CUcontext context);

int cuda_fill(CUcontext context, CUdevice device, void *ptr, size_t size,
              const void *pattern, size_t pattern_size);

int cuda_copy(CUcontext context, CUdevice device, void *dst_ptr, void *src_ptr,
              size_t size);

umf_usm_memory_type_t get_mem_type(CUcontext context, void *ptr);

CUcontext get_mem_context(void *ptr);

CUcontext get_current_context();

cuda_memory_provider_params_t
create_cuda_prov_params(umf_usm_memory_type_t memory_type);

#ifdef __cplusplus
}
#endif

#endif // TEST_COMMON_CUDA_HELPERS_HPP
