/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

// disable warning 4100: "unreferenced formal parameter" thrown in hwloc.h, as
// we do not want to modify this file
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4100)
#endif // _MSC_VER

// disable warning "unused parameter" thrown in hwloc.h
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif // defined(__GNUC__) || defined(__clang__)

#include <hwloc.h>

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif // defined(__GNUC__) || defined(__clang__)

#if defined(_MSC_VER)
#pragma warning(pop)
#endif // _MSC_VER
