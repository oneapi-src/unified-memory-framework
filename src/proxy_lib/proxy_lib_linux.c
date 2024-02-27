/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "proxy_lib.h"

// Priority forces this ctor to be called after both libumf and
// base_alloc ctors were called
void __attribute__((constructor(103))) proxy_lib_create(void) {
    proxy_lib_create_common();
}

// Priority forces this dtor to be called before both libumf and
// base_alloc dtors were called
void __attribute__((destructor(103))) proxy_lib_destroy(void) {
    proxy_lib_destroy_common();
}
