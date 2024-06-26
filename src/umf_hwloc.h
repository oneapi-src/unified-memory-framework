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

#include <hwloc.h>

#if defined(_MSC_VER)
#pragma warning(pop)
#endif // _MSC_VER
