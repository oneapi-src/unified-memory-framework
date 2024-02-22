/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "proxy_lib.h"

// The priority 102 is used, because the constructor should be called as the second one
// (just after the first constructor of the base allocator with priority 101)
// and the destructor as the last but one (just before the last destructor
// of the base allocator with priority 101), because this library
// provides the memory allocation API.
void __attribute__((constructor(102))) proxy_lib_create(void) {
    proxy_lib_create_common();
}

void __attribute__((destructor(102))) proxy_lib_destroy(void) {
    proxy_lib_destroy_common();
}
