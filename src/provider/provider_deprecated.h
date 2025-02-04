/*
 *
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_PROVIDER_DEPRECATED_H
#define UMF_PROVIDER_DEPRECATED_H 1

#include <umf/base.h>

#ifdef __cplusplus
extern "C" {
#endif

// define Memory Provider ops structure 0.10
// NOTE: in UMF 0.10 the free() was optional and was a part of the "ext"
// structure
typedef struct umf_memory_provider_ext_ops_0_10_t {
    umf_result_t (*free)(void *provider, void *ptr, size_t size);
    umf_result_t (*purge_lazy)(void *provider, void *ptr, size_t size);
    umf_result_t (*purge_force)(void *provider, void *ptr, size_t size);
    umf_result_t (*allocation_merge)(void *hProvider, void *lowPtr,
                                     void *highPtr, size_t totalSize);
    umf_result_t (*allocation_split)(void *hProvider, void *ptr,
                                     size_t totalSize, size_t firstSize);
} umf_memory_provider_ext_ops_0_10_t;

typedef struct umf_memory_provider_ipc_ops_0_10_t {
    umf_result_t (*get_ipc_handle_size)(void *provider, size_t *size);
    umf_result_t (*get_ipc_handle)(void *provider, const void *ptr, size_t size,
                                   void *providerIpcData);
    umf_result_t (*put_ipc_handle)(void *provider, void *providerIpcData);
    umf_result_t (*open_ipc_handle)(void *provider, void *providerIpcData,
                                    void **ptr);
    umf_result_t (*close_ipc_handle)(void *provider, void *ptr, size_t size);
} umf_memory_provider_ipc_ops_0_10_t;

typedef struct umf_memory_provider_ops_0_10_t {
    uint32_t version;
    umf_result_t (*initialize)(void *params, void **provider);
    void (*finalize)(void *provider);
    umf_result_t (*alloc)(void *provider, size_t size, size_t alignment,
                          void **ptr);
    void (*get_last_native_error)(void *provider, const char **ppMessage,
                                  int32_t *pError);
    umf_result_t (*get_recommended_page_size)(void *provider, size_t size,
                                              size_t *pageSize);
    umf_result_t (*get_min_page_size)(void *provider, void *ptr,
                                      size_t *pageSize);
    const char *(*get_name)(void *provider);
    umf_memory_provider_ext_ops_0_10_t ext;
    umf_memory_provider_ipc_ops_0_10_t ipc;
} umf_memory_provider_ops_0_10_t;

umf_result_t umfDefaultFree_0_10(void *provider, void *ptr, size_t size);

umf_result_t
umfTranslateMemoryProviderOps_0_10(umf_memory_provider_ops_0_10_t *ops_0_10,
                                   umf_memory_provider_ops_t *ops);

#ifdef __cplusplus
}
#endif

#endif /* #ifndef UMF_PROVIDER_DEPRECATED_H */
