/*
 *
 * Copyright (C) 2023-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <limits.h>

#include "utils_math.h"

// Retrieves the position of the leftmost set bit.
// The position of the bit is counted from 0
// e.g. for 01000011110 the position equals 9.
size_t utils_get_leftmost_set_bit_pos(uint64_t num) {
    assert(num != 0 &&
           "Finding leftmost set bit when number equals zero is undefined");
    return (sizeof(num) * CHAR_BIT - 1) - __builtin_clzll(num);
}

size_t utils_get_rightmost_set_bit_pos(uint64_t num) {
    assert(num != 0 &&
           "Finding rightmost set bit when number equals zero is undefined");
    return __builtin_ctzll(num);
}
