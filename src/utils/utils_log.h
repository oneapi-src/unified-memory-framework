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

typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR,
    LOG_FATAL
} utils_log_level_t;

#define LOG_DEBUG(...) utils_log(LOG_DEBUG, __func__, __VA_ARGS__);
#define LOG_INFO(...) utils_log(LOG_INFO, __func__, __VA_ARGS__);
#define LOG_WARN(...) utils_log(LOG_WARNING, __func__, __VA_ARGS__);
#define LOG_ERR(...) utils_log(LOG_ERROR, __func__, __VA_ARGS__);
#define LOG_FATAL(...) utils_log(LOG_FATAL, __func__, __VA_ARGS__);

#define LOG_PDEBUG(...) utils_plog(LOG_DEBUG, __func__, __VA_ARGS__);
#define LOG_PINFO(...) utils_plog(LOG_INFO, __func__, __VA_ARGS__);
#define LOG_PWARN(...) utils_plog(LOG_WARNING, __func__, __VA_ARGS__);
#define LOG_PERR(...) utils_plog(LOG_ERROR, __func__, __VA_ARGS__);
#define LOG_PFATAL(...) utils_plog(LOG_FATAL, __func__, __VA_ARGS__);

void utils_log_init(void);
#ifdef _WIN32
void utils_log(utils_log_level_t level, const char *func, const char *format,
               ...);
void utils_plog(utils_log_level_t level, const char *func, const char *format,
                ...);
#else
void utils_log(utils_log_level_t level, const char *func, const char *format,
               ...) __attribute__((format(printf, 3, 4)));
void utils_plog(utils_log_level_t level, const char *func, const char *format,
                ...) __attribute__((format(printf, 3, 4)));
#endif

#ifdef __cplusplus
}
#endif

#endif /* UMF_LOG_H */
