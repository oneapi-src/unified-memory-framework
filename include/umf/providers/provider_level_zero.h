/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#ifndef UMF_PROVIDER_LEVEL_ZERO_H
#define UMF_PROVIDER_LEVEL_ZERO_H

#include "umf/memory_provider.h"

#ifdef __cplusplus
extern "C" {
#endif

/// @brief Level Zero Memory Provider settings struct
typedef struct level_zero_memory_provider_params_t {
    void *level_zero_context_handle;   ///< Handle to the Level Zero context
    void *level_zero_device_handle;    ///< Handle to the Level Zero device
    umf_usm_memory_type_t memory_type; ///< Allocation memory type
} level_zero_memory_provider_params_t;

umf_memory_provider_ops_t *umfLevelZeroMemoryProviderOps(void);

#ifdef __cplusplus
}
#endif

#endif /* UMF_PROVIDER_LEVEL_ZERO_H */
