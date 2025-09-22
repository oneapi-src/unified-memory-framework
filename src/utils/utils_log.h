/*
 *
 * Copyright (C) 2024-2025 Intel Corporation
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

#include "ctl/ctl_internal.h"

typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR,
    LOG_FATAL
} utils_log_level_t;

#ifdef UMF_DEVELOPER_MODE
#define UMF_STRINGIFY(x) #x
#define UMF_TOSTRING(x) UMF_STRINGIFY(x)
#define UMF_FUNC_DESC() __FILE__ ":" UMF_TOSTRING(__LINE__)
#else
#define UMF_FUNC_DESC() __func__
#endif

#define LOG_DEBUG(...) utils_log(LOG_DEBUG, UMF_FUNC_DESC(), __VA_ARGS__);
#define LOG_INFO(...) utils_log(LOG_INFO, UMF_FUNC_DESC(), __VA_ARGS__);
#define LOG_WARN(...) utils_log(LOG_WARNING, UMF_FUNC_DESC(), __VA_ARGS__);
#define LOG_ERR(...) utils_log(LOG_ERROR, UMF_FUNC_DESC(), __VA_ARGS__);
#define LOG_FATAL(...) utils_log(LOG_FATAL, UMF_FUNC_DESC(), __VA_ARGS__);

#define LOG_PDEBUG(...) utils_plog(LOG_DEBUG, UMF_FUNC_DESC(), __VA_ARGS__);
#define LOG_PINFO(...) utils_plog(LOG_INFO, UMF_FUNC_DESC(), __VA_ARGS__);
#define LOG_PWARN(...) utils_plog(LOG_WARNING, UMF_FUNC_DESC(), __VA_ARGS__);
#define LOG_PERR(...) utils_plog(LOG_ERROR, UMF_FUNC_DESC(), __VA_ARGS__);
#define LOG_PFATAL(...) utils_plog(LOG_FATAL, UMF_FUNC_DESC(), __VA_ARGS__);

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

extern const umf_ctl_node_t CTL_NODE(logger)[];

#ifdef __cplusplus
}
#endif

#endif /* UMF_LOG_H */
