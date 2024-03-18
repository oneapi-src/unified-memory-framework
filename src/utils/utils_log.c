/*
 *
 * Copyright (C) 2024 Intel Corporation
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

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "utils_assert.h"
#include "utils_common.h"
#include "utils_log.h"

#define LOG_MAX 8192
#define LOG_HEADER 256
#define MAX_FILE_PATH 256
#define MAX_ENV_LEN 2048

typedef struct {
    int timestamp;
    int pid;
    util_log_level_t level;
    util_log_level_t flushLevel;
    FILE *output;
} util_log_config_t;

util_log_config_t loggerConfig = {0, 0, LOG_ERROR, LOG_ERROR, NULL};

static const char *level_to_str(util_log_level_t l) {
    switch (l) {
    case LOG_DEBUG:
        return "DEBUG";
    case LOG_ERROR:
        return "ERROR";
    case LOG_INFO:
        return "INFO";
    case LOG_WARNING:
        return "WARN";
    default:
        ASSERT(0);
        return "";
    }
}

void util_log(util_log_level_t level, const char *format, ...) {
    if (!loggerConfig.output) {
        return; //logger not enabled
    }
    if (level < loggerConfig.level) {
        return;
    }

#if defined(_WIN32)
    DWORD pid = GetCurrentProcessId();
    DWORD tid = GetCurrentThreadId();
#elif defined(__APPLE__)
    pid_t pid = getpid();
    uint64_t tid64;
    pthread_threadid_np(NULL, &tid64);
    pid_t tid = (pid_t)tid64;
#else
    pid_t pid = getpid();
    pid_t tid = gettid();
#endif

    char buffer[LOG_MAX];
    va_list args;
    va_start(args, format);
    int ret = vsnprintf(buffer, sizeof(buffer), format, args);
    const char *overflow = "";
    if (ret >= (intptr_t)sizeof(buffer)) {
        //TODO: alloc bigger buffer with base alloc
        overflow = "[truncated...]";
    }
    va_end(args);
    char header[LOG_HEADER];
    char *h_pos = header;
    memset(header, 0, sizeof(header));

    if (loggerConfig.timestamp) {
        time_t now = time(NULL);
        struct tm tm_info;
#ifdef _WIN32
        localtime_s(&tm_info, &now);
#else
        localtime_r(&now, &tm_info);
#endif

        ASSERT((intptr_t)sizeof(header) > (h_pos - header));
        h_pos += strftime(h_pos, sizeof(header) - (h_pos - header),
                          "%Y-%m-%dT%H:%M:%S ", &tm_info);
    }

    if (loggerConfig.pid) {
        ASSERT((intptr_t)sizeof(header) > (h_pos - header));
        h_pos += snprintf(h_pos, sizeof(header) - (h_pos - header),
                          "PID:%-6lu TID:%-6lu ", (unsigned long)pid,
                          (unsigned long)tid);
    }

    // We take twice header size here to ensure that
    // we have space for log level and overflow string
    // otherwise -Wformat-truncation might be thrown by compiler
    char logLine[LOG_MAX + LOG_HEADER * 2];
    snprintf(logLine, sizeof(logLine), "[%s%-5s UMF] %s%s\n", header,
             level_to_str(level), buffer, overflow);

    fputs(logLine, loggerConfig.output);

    if (level >= loggerConfig.flushLevel) {
        fflush(loggerConfig.output);
    }
}

static const char *bool_to_str(int b) { return b ? "yes" : "no"; }

void util_log_init(void) {
    const char *envVar = getenv("UMF_LOG");

    if (!envVar) {
        return;
    }

    const char *arg;
    if (util_parse_var(envVar, "output:stdout", NULL)) {
        loggerConfig.output = stdout;
    } else if (util_parse_var(envVar, "output:stderr", NULL)) {
        loggerConfig.output = stderr;
    } else if (util_parse_var(envVar, "output:file", &arg)) {
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
        loggerConfig.output = fopen(file, "w");
        if (!loggerConfig.output) {
            loggerConfig.output = stderr;
            LOG_ERR("Cannot open output file %s - logging disabled", file);
            loggerConfig.output = NULL;
            return;
        }
    } else {
        loggerConfig.output = stderr;
        LOG_ERR("Logging output not set - logging disabled");
        loggerConfig.output = NULL;
        return;
    }

    if (util_parse_var(envVar, "timestamp:yes", NULL)) {
        loggerConfig.timestamp = 1;
    } else if (util_parse_var(envVar, "timestamp:no", NULL)) {
        loggerConfig.timestamp = 0;
    }

    if (util_parse_var(envVar, "pid:yes", NULL)) {
        loggerConfig.pid = 1;
    } else if (util_parse_var(envVar, "pid:no", NULL)) {
        loggerConfig.pid = 0;
    }

    if (util_parse_var(envVar, "level:debug", NULL)) {
        loggerConfig.level = LOG_DEBUG;
    } else if (util_parse_var(envVar, "level:info", NULL)) {
        loggerConfig.level = LOG_INFO;
    } else if (util_parse_var(envVar, "level:warning", NULL)) {
        loggerConfig.level = LOG_WARNING;
    } else if (util_parse_var(envVar, "level:error", NULL)) {
        loggerConfig.level = LOG_ERROR;
    }

    if (util_parse_var(envVar, "flush:debug", NULL)) {
        loggerConfig.flushLevel = LOG_DEBUG;
    } else if (util_parse_var(envVar, "flush:info", NULL)) {
        loggerConfig.flushLevel = LOG_INFO;
    } else if (util_parse_var(envVar, "flush:warning", NULL)) {
        loggerConfig.flushLevel = LOG_WARNING;
    } else if (util_parse_var(envVar, "flush:error", NULL)) {
        loggerConfig.flushLevel = LOG_ERROR;
    }

    LOG_INFO(
        "Logger enabled (level: %s, flush: %s, pid: %s, timestamp: %s)",
        level_to_str(loggerConfig.level), level_to_str(loggerConfig.flushLevel),
        bool_to_str(loggerConfig.pid), bool_to_str(loggerConfig.timestamp));
}
