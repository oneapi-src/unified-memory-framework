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

// malloc API handlers
typedef void (*umf_proxy_lib_handler_free_post_t)(
    void *ptr, umf_memory_pool_handle_t pool);

void umfSetProxyLibHandlerFreePost(umf_proxy_lib_handler_free_post_t handler);

#ifdef __cplusplus
}
#endif

#endif /* UMF_PROXY_LIB_HANDLERS_H */
