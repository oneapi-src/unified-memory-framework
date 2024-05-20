/*
 *
 * Copyright (C) 2023-2024 Intel Corporation
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

// UMF representation of IPC handle. It contains UMF-specific common data
// and provider-specific IPC data, stored in providerIpcData.
// providerIpcData is a Flexible Array Member because its size varies
// depending on the provider.
typedef struct umf_ipc_data_t {
    int pid;         // process ID of the process that allocated the memory
    size_t baseSize; // size of base (coarse-grain) allocation
    uint64_t offset;
    char providerIpcData[];
} umf_ipc_data_t;

#ifdef __cplusplus
}
#endif

#endif /* UMF_IPC_INTERNAL_H */
