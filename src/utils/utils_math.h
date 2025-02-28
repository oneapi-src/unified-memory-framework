/*
 *
 * Copyright (C) 2023-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_MATH_H
#define UMF_MATH_H 1

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t utils_get_leftmost_set_bit_pos(uint64_t num);
size_t utils_get_rightmost_set_bit_pos(uint64_t num);

#ifdef __cplusplus
}
#endif

#endif /* UMF_MATH_H */
