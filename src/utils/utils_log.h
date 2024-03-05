/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_LOG_H
#define UMF_LOG_H 1

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { LOG_DEBUG, LOG_INFO, LOG_WARNING, LOG_ERROR } util_log_level_t;

void util_log_init(void);
void util_log(util_log_level_t level, const char *format, ...);

#define LOG_DEBUG(...) util_log(LOG_DEBUG, __VA_ARGS__);
#define LOG_INFO(...) util_log(LOG_INFO, __VA_ARGS__);
#define LOG_WARN(...) util_log(LOG_WARNING, __VA_ARGS__);
#define LOG_ERR(...) util_log(LOG_ERROR, __VA_ARGS__);

#ifdef __cplusplus
}
#endif

#endif /* UMF_LOG_H */
