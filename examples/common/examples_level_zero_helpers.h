/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_EXAMPLES_LEVEL_ZERO_H
#define UMF_EXAMPLES_LEVEL_ZERO_H

// To use the Level Zero API, the Level Zero SDK has to be installed
// on the system
#ifdef _WIN32
#include <ze_api.h>
#else
#include <level_zero/ze_api.h>
#endif

int init_level_zero(void);

int create_context(ze_driver_handle_t driver, ze_context_handle_t *context);

int destroy_context(ze_context_handle_t context);

int find_driver_with_gpu(uint32_t *driver_idx, ze_driver_handle_t *driver_);

int find_gpu_device(ze_driver_handle_t driver, ze_device_handle_t *device_);

int level_zero_fill(ze_context_handle_t context, ze_device_handle_t device,
                    void *ptr, size_t size, const void *pattern,
                    size_t pattern_size);

int level_zero_copy(ze_context_handle_t context, ze_device_handle_t device,
                    void *dst_ptr, void *src_ptr, size_t size);

#endif /* UMF_EXAMPLES_LEVEL_ZERO_H */
