/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_IPC_INTERNAL_H
#define UMF_IPC_INTERNAL_H 1

#include <umf/base.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct umf_ipc_data_t {
    size_t size; // size of base allocation
    uint64_t offset;
    char providerData[];
} umf_ipc_data_t;

#ifdef __cplusplus
}
#endif

#endif /* UMF_IPC_INTERNAL_H */
