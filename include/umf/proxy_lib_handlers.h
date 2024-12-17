/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#ifndef UMF_PROXY_LIB_HANDLERS_H
#define UMF_PROXY_LIB_HANDLERS_H 1

#include <umf/memory_pool.h>

#ifdef __cplusplus
extern "C" {
#endif

// TODO - improve and cleanup comments

// malloc API handlers
// NOTE - in malloc/aligned_malloc pre handlers the default pool could be
// changed along with the requested size and alignment
// - in free pre handler user can update the ptr
typedef void (*umf_proxy_lib_handler_malloc_pre_t)(void *user_data,
                                                   size_t *size);
typedef void (*umf_proxy_lib_handler_aligned_malloc_pre_t)(
    void *user_data, umf_memory_pool_handle_t *pool, size_t *size,
    size_t *alignment);
typedef void (*umf_proxy_lib_handler_free_pre_t)(void *user_data, void **ptr,
                                                 umf_memory_pool_handle_t pool);

void umfSetProxyLibHandlerMallocPre(umf_proxy_lib_handler_malloc_pre_t handler,
                                    void *user_data);
void umfSetProxyLibHandlerAlignedMallocPre(
    umf_proxy_lib_handler_aligned_malloc_pre_t handler, void *user_data);
void umfSetProxyLibHandlerFreePre(umf_proxy_lib_handler_free_pre_t handler,
                                  void *user_data);

// NOTE - in the malloc/aligned_malloc post handlers the pointer to allocated
// data could be changed by the user
typedef void (*umf_proxy_lib_handler_malloc_post_t)(
    void *user_data, void **ptr, umf_memory_pool_handle_t pool);
typedef void (*umf_proxy_lib_handler_aligned_malloc_post_t)(
    void *user_data, void **ptr, umf_memory_pool_handle_t pool);

void umfSetProxyLibHandlerMallocPost(
    umf_proxy_lib_handler_malloc_post_t handler, void *user_data);
void umfSetProxyLibHandlerAlignedMallocPost(
    umf_proxy_lib_handler_aligned_malloc_post_t handler, void *user_data);

#ifdef __cplusplus
}
#endif

#endif /* UMF_PROXY_LIB_HANDLERS_H */
