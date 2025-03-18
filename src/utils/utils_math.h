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
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)

#include "utils_windows_intrin.h"

#pragma intrinsic(_BitScanReverse64)
#pragma intrinsic(_BitScanForward64)

// Retrieves the position of the leftmost set bit.
// The position of the bit is counted from 0
// e.g. for 01000011110 the position equals 9.
static inline size_t utils_msb64(uint64_t num) {
    assert(num != 0 &&
           "Finding leftmost set bit when number equals zero is undefined");
    unsigned long index = 0;
    _BitScanReverse64(&index, num);
    return (size_t)index;
}

static inline size_t utils_lsb64(uint64_t num) {
    assert(num != 0 &&
           "Finding rightmost set bit when number equals zero is undefined");
    unsigned long index = 0;
    _BitScanForward64(&index, num);
    return (size_t)index;
}

#else // !defined(_WIN32)

// Retrieves the position of the leftmost set bit.
// The position of the bit is counted from 0
// e.g. for 01000011110 the position equals 9.
static inline size_t utils_msb64(uint64_t num) {
    assert(num != 0 &&
           "Finding leftmost set bit when number equals zero is undefined");
    return 63 - __builtin_clzll(num);
}

static inline size_t utils_lsb64(uint64_t num) {
    assert(num != 0 &&
           "Finding rightmost set bit when number equals zero is undefined");
    return __builtin_ctzll(num);
}

#endif // !defined(_WIN32)

#ifdef __cplusplus
}
#endif

#endif /* UMF_MATH_H */
