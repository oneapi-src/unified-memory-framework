/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <umf.h>

void __attribute__((constructor)) umfCreate(void) { (void)umfInit(); }

void __attribute__((destructor)) umfDestroy(void) { umfTearDown(); }

void libumfInit(void) {
    // do nothing, additional initialization not needed
}
