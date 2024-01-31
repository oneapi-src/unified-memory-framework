/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#ifndef __SANITIZE_THREAD__
#define __SANITIZE_THREAD__ 1
#endif
#endif
#endif

#if __SANITIZE_THREAD__
#include <sanitizer/tsan_interface.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

void utils_annotate_acquire(void *ptr) {
#if __SANITIZE_THREAD__
    __tsan_acquire(ptr);
#else
    (void)ptr;
#endif
}

void utils_annotate_release(void *ptr) {
#if __SANITIZE_THREAD__
    __tsan_release(ptr);
#else
    (void)ptr;
#endif
}

#ifdef __cplusplus
}
#endif
