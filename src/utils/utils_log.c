/*
 *
 * Copyright (C) 2024-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifdef _WIN32
#include <windows.h>
#else
#define _GNU_SOURCE 1
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#ifdef __APPLE__
#include <pthread.h>
#endif

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <umf.h>

#include "ctl/ctl_internal.h"
#include "utils_assert.h"
#include "utils_common.h"
#include "utils_log.h"

#define UMF_MAGIC_STR "\x00@(#) "
#define UMF_PREF_STR "Intel(R) "
#define UMF_PREFIX UMF_MAGIC_STR UMF_PREF_STR

// convert a define to a C string
#define STR_(X) #X
#define STR(X) STR_(X)

#ifdef UMF_VERSION
#define STR_UMF_VERSION "UMF version: " STR(UMF_VERSION)
#define LOG_STR_UMF_VERSION STR_UMF_VERSION ", "
char const __umf_str_2_version[] = UMF_PREFIX STR_UMF_VERSION;
#else /* !UMF_VERSION */
#error "UMF_VERSION not defined!"
#endif /* !UMF_VERSION */

#ifdef UMF_ALL_CMAKE_VARIABLES
char const __umf_str_1__all_cmake_vars[] =
    UMF_PREFIX "UMF CMake variables: " STR(UMF_ALL_CMAKE_VARIABLES);
#else /* !UMF_ALL_CMAKE_VARIABLES */
#error "UMF_ALL_CMAKE_VARIABLES not defined!"
#endif /* !UMF_ALL_CMAKE_VARIABLES */

#define LOG_MAX 8192
#define LOG_HEADER 256
#define MAX_FILE_PATH 256
#define MAX_ENV_LEN 2048

typedef struct {
    bool enableTimestamp;
    bool enablePid;
    utils_log_level_t level;
    utils_log_level_t flushLevel;
    FILE *output;
    const char *file_name;
} utils_log_config_t;

utils_log_config_t loggerConfig = {false,     false, LOG_ERROR,
                                   LOG_ERROR, NULL,  NULL};

static const char *level_to_str(utils_log_level_t l) {
    switch (l) {
    case LOG_DEBUG:
        return "DEBUG";
    case LOG_ERROR:
        return "ERROR";
    case LOG_INFO:
        return "INFO";
    case LOG_WARNING:
        return "WARN";
    case LOG_FATAL:
        return "FATAL";
    default:
        ASSERT(0);
        return "";
    }
}

// disable warning 6262: "function uses '17368' bytes of stack. Consider moving
// some data to heap", since we use such large buffers intentionally to fit all
// the data
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 6262)
#endif // _MSC_VER

static void utils_log_internal(utils_log_level_t level, int perror,
                               const char *func, const char *format,
                               va_list args) {
    if (!loggerConfig.output && level != LOG_FATAL) {
        return; //logger not enabled
    }
    if (level < loggerConfig.level) {
        return;
    }

    int pid = utils_getpid();
    int tid = utils_gettid();

    char buffer[LOG_MAX];
    char *b_pos = buffer;
    int b_size = sizeof(buffer);

    int tmp = snprintf(b_pos, b_size, "%s: ", func);
    ASSERT(tmp > 0);

    b_pos += (int)tmp;
    b_size -= (int)tmp;

    tmp = vsnprintf(b_pos, b_size, format, args);
    ASSERT(tmp > 0);

    b_pos += (int)tmp;
    b_size -= (int)tmp;

    const char *postfix = "";

    if (perror) {
        if (b_size > 2) {
            strncat(b_pos, ": ", b_size);
            b_pos += 2;
            b_size -= 2;
#if defined(_WIN32)
            char err[80]; // max size according to msdn
            if (strerror_s(err, sizeof(err), errno)) {
                *err = '\0';
                postfix = "[strerror_s failed]";
            }
#elif defined(__APPLE__)
            char err[1024]; // max size according to manpage.
            int saveno = errno;
            errno = 0;
            if (strerror_r(saveno, err, sizeof(err))) {
                /* should never happen */
                *err = '\0';
                postfix = "[strerror_r failed]";
            }

            if (errno == ERANGE) {
                postfix = "[truncated...]";
            }
            errno = saveno;
#else
            char err_buff[1024]; // max size according to manpage.
            int saveno = errno;
            errno = 0;
            const char *err = strerror_r(saveno, err_buff, sizeof(err_buff));
            if (errno == ERANGE) {
                postfix = "[truncated...]";
            }
            errno = saveno;
#endif
            strncpy(b_pos, err, b_size);
            size_t err_size = strlen(err);
            b_pos += err_size;
            b_size -= (int)err_size;
            if (b_size <= 0) {
                buffer[LOG_MAX - 1] =
                    '\0'; //strncpy do not add \0 in case of overflow
            }
        } else {
            postfix = "[truncated...]";
        }
    }

    if (b_size <= 0) {
        //TODO: alloc bigger buffer with base alloc
        postfix = "[truncated...]";
    }

    char header[LOG_HEADER];
    char *h_pos = header;
    int h_size = sizeof(header);
    memset(header, 0, sizeof(header));

    if (loggerConfig.enableTimestamp) {
        time_t now = time(NULL);
        struct tm tm_info;
#ifdef _WIN32
        localtime_s(&tm_info, &now);
#else
        localtime_r(&now, &tm_info);
#endif

        ASSERT(h_size > 0);
        tmp = (int)strftime(h_pos, h_size, "%Y-%m-%dT%H:%M:%S ", &tm_info);
        h_pos += tmp;
        h_size -= tmp;
    }

    if (loggerConfig.enablePid) {
        ASSERT(h_size > 0);
        tmp = snprintf(h_pos, h_size, "PID:%-6lu TID:%-6lu ",
                       (unsigned long)pid, (unsigned long)tid);
        h_pos += tmp;
        h_size -= tmp;
    }

    // We take twice header size here to ensure that
    // we have space for log level and postfix string
    // otherwise -Wformat-truncation might be thrown by compiler
    char logLine[LOG_MAX + LOG_HEADER * 2];
    snprintf(logLine, sizeof(logLine), "[%s%-5s UMF] %s%s\n", header,
             level_to_str(level), buffer, postfix);
    FILE *out = loggerConfig.output ? loggerConfig.output : stderr;
    fputs(logLine, out);

    if (level >= loggerConfig.flushLevel) {
        fflush(out);
    }
}

#if defined(_MSC_VER)
#pragma warning(pop)
#endif // _MSC_VER

void utils_log(utils_log_level_t level, const char *func, const char *format,
               ...) {
    va_list args;
    va_start(args, format);
    utils_log_internal(level, 0, func, format, args);
    va_end(args);
}

void utils_plog(utils_log_level_t level, const char *func, const char *format,
                ...) {
    va_list args;
    va_start(args, format);
    utils_log_internal(level, 1, func, format, args);
    va_end(args);
}

static const char *bool_to_str(int b) { return b ? "yes" : "no"; }

void utils_log_init(void) {
    const char *envVar = getenv("UMF_LOG");

    if (!envVar) {
        return;
    }

    const char *arg;
    if (utils_parse_var(envVar, "output:stdout", NULL)) {
        loggerConfig.output = stdout;
        loggerConfig.file_name = "stdout";
    } else if (utils_parse_var(envVar, "output:stderr", NULL)) {
        loggerConfig.output = stderr;
        loggerConfig.file_name = "stderr";
    } else if (utils_parse_var(envVar, "output:file", &arg)) {
        loggerConfig.output = NULL;
        const char *argEnd = strstr(arg, ";");
        char file[MAX_FILE_PATH + 1];
        size_t len = 0;

        if (argEnd) {
            len = argEnd - arg;
        } else {
            len = strlen(arg);
        }

        if (len > MAX_FILE_PATH) {
            loggerConfig.output = stderr;
            LOG_ERR("Cannot open output file - path too long");
            loggerConfig.output = NULL;
            return;
        }

        memcpy(file, arg, len);
        file[len] = '\0';
        loggerConfig.output = fopen(file, "a");
        if (!loggerConfig.output) {
            loggerConfig.output = stderr;
            LOG_PERR("Cannot open output file %s - logging disabled", file);
            loggerConfig.output = NULL;
            return;
        }
        loggerConfig.file_name = file;
    } else {
        loggerConfig.output = stderr;
        LOG_ERR("Logging output not set - logging disabled (UMF_LOG = \"%s\")",
                envVar);
        loggerConfig.output = NULL;
        return;
    }

    if (utils_parse_var(envVar, "timestamp:yes", NULL)) {
        loggerConfig.enableTimestamp = 1;
    } else if (utils_parse_var(envVar, "timestamp:no", NULL)) {
        loggerConfig.enableTimestamp = 0;
    }

    if (utils_parse_var(envVar, "pid:yes", NULL)) {
        loggerConfig.enablePid = 1;
    } else if (utils_parse_var(envVar, "pid:no", NULL)) {
        loggerConfig.enablePid = 0;
    }

    if (utils_parse_var(envVar, "level:debug", NULL)) {
        loggerConfig.level = LOG_DEBUG;
    } else if (utils_parse_var(envVar, "level:info", NULL)) {
        loggerConfig.level = LOG_INFO;
    } else if (utils_parse_var(envVar, "level:warning", NULL)) {
        loggerConfig.level = LOG_WARNING;
    } else if (utils_parse_var(envVar, "level:error", NULL)) {
        loggerConfig.level = LOG_ERROR;
    } else if (utils_parse_var(envVar, "level:fatal", NULL)) {
        loggerConfig.level = LOG_FATAL;
    }

    if (utils_parse_var(envVar, "flush:debug", NULL)) {
        loggerConfig.flushLevel = LOG_DEBUG;
    } else if (utils_parse_var(envVar, "flush:info", NULL)) {
        loggerConfig.flushLevel = LOG_INFO;
    } else if (utils_parse_var(envVar, "flush:warning", NULL)) {
        loggerConfig.flushLevel = LOG_WARNING;
    } else if (utils_parse_var(envVar, "flush:error", NULL)) {
        loggerConfig.flushLevel = LOG_ERROR;
    } else if (utils_parse_var(envVar, "flush:fatal", NULL)) {
        loggerConfig.flushLevel = LOG_FATAL;
    }

    LOG_INFO("Logger enabled (" LOG_STR_UMF_VERSION
             "level: %s, flush: %s, pid: %s, timestamp: %s)",
             level_to_str(loggerConfig.level),
             level_to_str(loggerConfig.flushLevel),
             bool_to_str(loggerConfig.enablePid),
             bool_to_str(loggerConfig.enableTimestamp));
}

// this is needed for logger unit test
#ifndef DISABLE_CTL_LOGGER
static umf_result_t
CTL_READ_HANDLER(timestamp)(void *ctx, umf_ctl_query_source_t source, void *arg,
                            size_t size, umf_ctl_index_utlist_t *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)indexes, (void)ctx;

    bool *arg_out = (bool *)arg;

    if (arg_out == NULL || size < sizeof(bool)) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *arg_out = loggerConfig.enableTimestamp;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t
CTL_WRITE_HANDLER(timestamp)(void *ctx, umf_ctl_query_source_t source,
                             void *arg, size_t size,
                             umf_ctl_index_utlist_t *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)indexes, (void)ctx;

    bool arg_in = *(bool *)arg;

    if (size < sizeof(bool)) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    loggerConfig.enableTimestamp = arg_in;
    LOG_INFO("Logger print timestamp set to %s",
             bool_to_str(loggerConfig.enableTimestamp));
    return UMF_RESULT_SUCCESS;
}

static umf_result_t CTL_READ_HANDLER(pid)(void *ctx,
                                          umf_ctl_query_source_t source,
                                          void *arg, size_t size,
                                          umf_ctl_index_utlist_t *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)indexes, (void)ctx;

    bool *arg_out = (bool *)arg;

    if (arg_out == NULL || size < sizeof(bool)) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *arg_out = loggerConfig.enablePid;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t CTL_WRITE_HANDLER(pid)(void *ctx,
                                           umf_ctl_query_source_t source,
                                           void *arg, size_t size,
                                           umf_ctl_index_utlist_t *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)indexes, (void)ctx;

    bool arg_in = *(bool *)arg;

    if (size < sizeof(bool)) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    loggerConfig.enablePid = arg_in;
    LOG_INFO("Logger print pid %s set to", bool_to_str(loggerConfig.enablePid));
    return UMF_RESULT_SUCCESS;
}

static umf_result_t CTL_READ_HANDLER(level)(void *ctx,
                                            umf_ctl_query_source_t source,
                                            void *arg, size_t size,
                                            umf_ctl_index_utlist_t *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)indexes, (void)ctx;

    bool *arg_out = (bool *)arg;

    if (arg_out == NULL || size < sizeof(utils_log_level_t)) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *arg_out = loggerConfig.level;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t CTL_WRITE_HANDLER(level)(void *ctx,
                                             umf_ctl_query_source_t source,
                                             void *arg, size_t size,
                                             umf_ctl_index_utlist_t *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)indexes, (void)ctx;

    utils_log_level_t *arg_in = (utils_log_level_t *)arg;

    if (arg_in == NULL || *arg_in < LOG_DEBUG || *arg_in > LOG_FATAL ||
        size < sizeof(int)) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    utils_log_level_t old = loggerConfig.level;

    // if new log level is higher then LOG_INFO print log before changing log level
    // so if user changes from LOG_INFO to higher log level, it will get information about change anyway
    if (*arg_in > LOG_INFO) {
        LOG_INFO("Logger level changed from %s to %s", level_to_str(old),
                 level_to_str(*arg_in));
        loggerConfig.level = *arg_in;
    } else {
        loggerConfig.level = *arg_in;
        LOG_INFO("Logger level changed from %s to %s", level_to_str(old),
                 level_to_str(loggerConfig.level));
    }

    return UMF_RESULT_SUCCESS;
}

static umf_result_t
CTL_READ_HANDLER(flush_level)(void *ctx, umf_ctl_query_source_t source,
                              void *arg, size_t size,
                              umf_ctl_index_utlist_t *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)indexes, (void)ctx;

    utils_log_level_t *arg_out = (utils_log_level_t *)arg;

    if (arg_out == NULL || size < sizeof(utils_log_level_t)) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *arg_out = loggerConfig.flushLevel;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t
CTL_WRITE_HANDLER(flush_level)(void *ctx, umf_ctl_query_source_t source,
                               void *arg, size_t size,
                               umf_ctl_index_utlist_t *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)indexes, (void)ctx;

    utils_log_level_t *arg_in = (utils_log_level_t *)arg;

    if (arg_in == NULL || *arg_in < LOG_DEBUG || *arg_in > LOG_FATAL ||
        size < sizeof(int)) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    loggerConfig.flushLevel = *arg_in;
    LOG_INFO("Logger flush level set to %s",
             level_to_str(loggerConfig.flushLevel));
    return UMF_RESULT_SUCCESS;
}

static umf_result_t CTL_READ_HANDLER(output)(void *ctx,
                                             umf_ctl_query_source_t source,
                                             void *arg, size_t size,
                                             umf_ctl_index_utlist_t *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)indexes, (void)ctx;

    const char **arg_out = (const char **)arg;
    if (arg_out == NULL || size < sizeof(const char *)) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (loggerConfig.output == NULL) {
        *arg_out = "disabled";
        return UMF_RESULT_SUCCESS;
    }

    *arg_out = loggerConfig.file_name;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t CTL_WRITE_HANDLER(output)(void *ctx,
                                              umf_ctl_query_source_t source,
                                              void *arg, size_t size,
                                              umf_ctl_index_utlist_t *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)indexes, (void)ctx;

    const char *arg_in = *(const char **)arg;
    if (size < sizeof(const char *)) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    FILE *oldHandle = loggerConfig.output;
    const char *oldName =
        loggerConfig.file_name ? loggerConfig.file_name : "disabled";

    if (arg_in == NULL) {
        if (loggerConfig.output) {
            LOG_INFO("Logger disabled");
            if (oldHandle != stdout && oldHandle != stderr) {
                fclose(oldHandle);
            }
            loggerConfig.output = NULL;
            loggerConfig.file_name = NULL;
        }
        return UMF_RESULT_SUCCESS;
    }

    FILE *newHandle = NULL;

    if (strcmp(arg_in, "stdout") == 0) {
        newHandle = stdout;
        loggerConfig.file_name = "stdout";
    } else if (strcmp(arg_in, "stderr") == 0) {
        newHandle = stderr;
        loggerConfig.file_name = "stderr";
    } else {
        newHandle = fopen(arg_in, "a");
        if (!newHandle) {
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
        loggerConfig.file_name = arg_in;
    }

    loggerConfig.output = newHandle;
    LOG_INFO("Logger output changed from %s to %s", oldName,
             loggerConfig.file_name);

    if (oldHandle && oldHandle != stdout && oldHandle != stderr) {
        fclose(oldHandle);
    }

    return UMF_RESULT_SUCCESS;
}

static const struct ctl_argument CTL_ARG(timestamp) = CTL_ARG_BOOLEAN;
static const struct ctl_argument CTL_ARG(pid) = CTL_ARG_BOOLEAN;
static const struct ctl_argument CTL_ARG(level) = CTL_ARG_INT;
static const struct ctl_argument CTL_ARG(flush_level) = CTL_ARG_INT;
static const struct ctl_argument
    CTL_ARG(output) = CTL_ARG_STRING(MAX_FILE_PATH);

const umf_ctl_node_t CTL_NODE(logger)[] = {
    CTL_LEAF_RW(timestamp),   CTL_LEAF_RW(pid),    CTL_LEAF_RW(level),
    CTL_LEAF_RW(flush_level), CTL_LEAF_RW(output), CTL_NODE_END,
};
#endif
