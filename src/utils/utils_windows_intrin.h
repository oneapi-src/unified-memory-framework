/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_UTILS_WINDOWS_INTRIN_H
#define UMF_UTILS_WINDOWS_INTRIN_H 1

#ifdef _WIN32

// Disable warning 28251: "inconsistent annotation for function" thrown in
// intrin.h, as we do not want to modify this file.
#pragma warning(push)
#pragma warning(disable : 28251)

#include <intrin.h>

#pragma warning(pop)

#endif /* _WIN32 */

#endif /* UMF_UTILS_WINDOWS_INTRIN_H */
