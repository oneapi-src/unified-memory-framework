// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// This file contains helpers for tests for UMF pool API

#ifndef UMF_TEST_HELPERS_LINUX_H
#define UMF_TEST_HELPERS_LINUX_H 1

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

bool is_mapped_with_MAP_SYNC(char *path, char *buf, size_t size_buf);

#ifdef __cplusplus
}
#endif

#endif /* UMF_TEST_HELPERS_LINUX_H */
