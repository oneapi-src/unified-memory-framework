/*
 *
 * Copyright (C) 2023-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "utils_math.h"
#include "utils_windows_intrin.h"

#pragma intrinsic(_BitScanReverse)

// Retrieves the position of the leftmost set bit.
// The position of the bit is counted from 0
// e.g. for 01000011110 the position equals 9.
size_t getLeftmostSetBitPos(size_t num) {
    assert(num != 0 &&
           "Finding leftmost set bit when number equals zero is undefined");
    unsigned long index = 0;
    _BitScanReverse(&index, (unsigned long)num);
    return (size_t)index;
}
