/*
 *
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_MATH_H
#define UMF_MATH_H 1

#include <assert.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t getLeftmostSetBitPos(size_t num);

// Logarithm is an index of the most significant non-zero bit.
static inline size_t log2Utils(size_t num) { return getLeftmostSetBitPos(num); }

#ifdef __cplusplus
}
#endif

#endif /* UMF_MATH_H */
