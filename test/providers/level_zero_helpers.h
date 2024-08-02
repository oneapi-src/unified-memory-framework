/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef UMF_TEST_LEVEL_ZERO_HELPERS_H
#define UMF_TEST_LEVEL_ZERO_HELPERS_H

#include <umf/providers/provider_level_zero.h>

#include "ze_api.h"

#ifdef __cplusplus
extern "C" {
#endif

int get_drivers(uint32_t *drivers_num_, ze_driver_handle_t **drivers_);

int get_devices(ze_driver_handle_t driver, uint32_t *devices_num_,
                ze_device_handle_t **devices_);

int find_driver_with_gpu(uint32_t *driver_idx, ze_driver_handle_t *driver_);

int find_gpu_device(ze_driver_handle_t driver, ze_device_handle_t *device_);

int level_zero_fill(ze_context_handle_t context, ze_device_handle_t device,
                    void *ptr, size_t size, const void *pattern,
                    size_t pattern_size);

int level_zero_copy(ze_context_handle_t context, ze_device_handle_t device,
                    void *dst_ptr, const void *src_ptr, size_t size);

int create_context(ze_driver_handle_t driver, ze_context_handle_t *context);

int destroy_context(ze_context_handle_t context);

ze_memory_type_t get_mem_type(ze_context_handle_t context, void *ptr);

level_zero_memory_provider_params_t
create_level_zero_prov_params(umf_usm_memory_type_t memory_type);

#ifdef __cplusplus
}
#endif

#endif // UMF_TEST_LEVEL_ZERO_HELPERS_H
