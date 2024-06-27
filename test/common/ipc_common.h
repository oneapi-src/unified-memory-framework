/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef IPC_COMMON_H
#define IPC_COMMON_H

#include <stdlib.h>

#include <umf/memory_provider.h>

// pointer to the function that returns void and accept two int values
typedef void (*memcopy_callback_t)(void *dst, const void *src, size_t size,
                                   void *context);

int producer_connect(int port);
int consumer_connect(int port);

int run_producer(int port, umf_memory_provider_ops_t *provider_ops,
                 void *provider_params, memcopy_callback_t memcopy_callback,
                 void *memcopy_ctx);
int run_consumer(int port, umf_memory_provider_ops_t *provider_ops,
                 void *provider_params, memcopy_callback_t memcopy_callback,
                 void *memcopy_ctx);

void memcopy(void *dst, const void *src, size_t size, void *context);

#endif // IPC_COMMON_H
