/*
 *
 * Copyright (C) 2024-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "proxy_lib.h"

void __attribute__((constructor)) proxy_lib_create(void) {
    proxy_lib_create_common();
}

void __attribute__((destructor)) proxy_lib_destroy(void) {
    proxy_lib_destroy_common();
}
