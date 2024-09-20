// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "base.hpp"
#include "test_helpers.h"

#define MOCK_FILE_PTR (FILE *)0xBADBEEF
#define INVALID_ERRNO 42
std::string expected_filename;
int expect_fopen_count = 0;
int fopen_count = 0;

FILE *mock_fopen(const char *filename, const char *mode) {
    fopen_count++;
    EXPECT_STREQ(filename, expected_filename.c_str());
    EXPECT_STREQ(mode, "a");
    return MOCK_FILE_PTR;
}

const std::string MOCK_FN_NAME = "MOCK_FUNCTION_NAME";
std::string expected_message = "[ERROR UMF] utils_log_init: Logging output not "
                               "set - logging disabled (UMF_LOG = \"\")\n";
// The expected_message (above) is printed to stderr.
FILE *expected_stream = stderr;
int expect_fput_count = 0;
int fput_count = 0;

int mock_fputs(const char *s, FILE *stream) {
    fput_count++;
    if (!expected_message.empty()) {
        EXPECT_STREQ(s, expected_message.c_str());
    }
    EXPECT_EQ(stream, expected_stream);
    return (int)strlen(s);
}

int expect_fflush_count = 0;
int fflush_count = 0;

int mock_fflush(FILE *stream) {
    fflush_count++;
    EXPECT_EQ(stream, expected_stream);
    return 0;
}

const char *strerr = "";
int strerror_ret_static = 1;
char *mock_strerror_gnu(int errnum, char *buff, size_t s) {
    if (errnum == INVALID_ERRNO) {
        errno = EINVAL;
        return (char *)"unknown error";
    }
    if (strerror_ret_static) {
        return (char *)strerr;
    }

    strncpy(buff, strerr, s);

    if (s < strlen(strerr)) {
        errno = ERANGE;
        buff[s - 1] = '\0';
    }
    return buff;
}

int mock_strerror_posix(int errnum, char *buff, size_t s) {
    if (errnum == INVALID_ERRNO) {
        errno = EINVAL;
        strncpy(buff, "unknown error", s);
    } else {
        strncpy(buff, strerr, s);
    }

    if (s < strlen(strerr)) {
        errno = ERANGE;
        buff[s - 1] = '\0';
    }
    return 0;
}

int mock_strerror_windows(char *buff, size_t s, int errnum) {
    if (errnum == INVALID_ERRNO) {
        strncpy(buff, "unknown error", s);
    } else {
        strncpy(buff, strerr, s);
    }

    if (s < strlen(strerr)) {
        buff[s - 1] = '\0';
    }
    return 0;
}

extern "C" {

const char *env_variable = "";
#define fopen(A, B) mock_fopen(A, B)
#define fputs(A, B) mock_fputs(A, B)
#define fflush(A) mock_fflush(A)
#define utils_env_var(A, B, C) mock_utils_env_var(A, B, C)
#if defined(__APPLE__)
#define strerror_r(A, B, C) mock_strerror_posix(A, B, C)
#else
#define strerror_r(A, B, C) mock_strerror_gnu(A, B, C)
#endif
#define strerror_s(A, B, C) mock_strerror_windows(A, B, C)
//getenv returns 'char *' not 'const char *' so we need explicit cast to drop const
#define getenv(X) strstr(X, "UMF_LOG") ? (char *)env_variable : getenv(X)
#ifndef UMF_VERSION
#define UMF_VERSION "test version"
#endif
#include "utils/utils_log.c"
#undef utils_env_var
#undef fopen
#undef fputs
#undef fflush
}
using umf_test::test;

void helper_log_init(const char *var) {
    env_variable = var;
    fopen_count = 0;
    fput_count = 0;
    utils_log_init();
    env_variable = NULL;
    EXPECT_EQ(fopen_count, expect_fopen_count);
    EXPECT_EQ(fput_count, expect_fput_count);
}

void helper_checkConfig(utils_log_config_t *expected, utils_log_config_t *is) {
    EXPECT_EQ(expected->level, is->level);
    EXPECT_EQ(expected->flushLevel, is->flushLevel);
    EXPECT_EQ(expected->output, is->output);
    EXPECT_EQ(expected->timestamp, is->timestamp);
    EXPECT_EQ(expected->pid, is->pid);
}

TEST_F(test, parseEnv_errors) {
    expected_message = "";
    loggerConfig = {0, 0, LOG_ERROR, LOG_ERROR, NULL};

    expect_fput_count = 0;
    expected_stream = stderr;
    utils_log_config_t b = loggerConfig;
    helper_log_init(NULL);
    helper_checkConfig(&b, &loggerConfig);

    expect_fput_count = 1;
    helper_log_init("");
    helper_checkConfig(&b, &loggerConfig);
    helper_log_init("invalidarg");
    helper_checkConfig(&b, &loggerConfig);
    helper_log_init("level:invalid");
    helper_checkConfig(&b, &loggerConfig);
    helper_log_init("_level:debug");
    helper_checkConfig(&b, &loggerConfig);
    expected_message =
        "[ERROR UMF] utils_log_init: Cannot open output file - path too long\n";
    std::string test_env = "output:file," + std::string(300, 'x');
    helper_log_init(test_env.c_str());
}

TEST_F(test, parseEnv) {
    utils_log_config_t b = loggerConfig;
    expected_message = "";

    std::vector<std::pair<std::string, int>> logLevels = {
        {"level:debug", LOG_DEBUG},
        {"level:info", LOG_INFO},
        {"level:invalid", LOG_ERROR},
        {"level:warning", LOG_WARNING},
        {"level:error", LOG_ERROR},
        {"level:fatal", LOG_FATAL},
        {"", LOG_ERROR}};

    std::vector<std::pair<std::string, int>> flushLevels = {
        {"flush:debug", LOG_DEBUG},
        {"flush:invalid", LOG_ERROR},
        {"flush:info", LOG_INFO},
        {"flush:warning", LOG_WARNING},
        {"flush:error", LOG_ERROR},
        {"flush:fatal", LOG_FATAL},
        {"", LOG_ERROR}};

    std::vector<std::pair<std::string, FILE *>> outputs = {
        {"output:stdout", stdout},
        {"output:stderr", stderr},
        {"", NULL},
        {"output:file,filepath", MOCK_FILE_PTR},
        {"output:file," + std::string(300, 'x'), NULL},
        {"output:file," + std::string(256, 'x'), MOCK_FILE_PTR},
        {"output:file," + std::string(257, 'x'), NULL},
    };
    std::vector<std::pair<std::string, int>> timestamps = {
        {"timestamp:yes", 1},
        {"timestamp:invalid", 0},
        {"timestamp:no", 0},
        {"", 0}};

    std::vector<std::pair<std::string, int>> pids = {
        {"pid:yes", 1}, {"pid:invalid", 0}, {"pid:no", 0}, {"", 0}};
    for (const auto &logLevel : logLevels) {
        for (const auto &flushLevel : flushLevels) {
            for (const auto &output : outputs) {
                for (const auto &timestamp : timestamps) {
                    for (const auto &pid : pids) {
                        std::string envVar = logLevel.first + ";" +
                                             flushLevel.first + ";" +
                                             output.first + ";" +
                                             timestamp.first + ";" + pid.first;
                        b = loggerConfig = {0, 0, LOG_ERROR, LOG_ERROR, NULL};
                        expect_fput_count = 0;
                        expect_fopen_count = 0;
                        expected_stream = stderr;
                        expected_message = "";
                        expected_filename = "";
                        auto n = output.first.find(',');
                        if (n != std::string::npos) {
                            expected_filename = output.first.substr(n + 1);
                        }

                        if (output.second != NULL) {
                            b.output = output.second;
                            if (output.second == MOCK_FILE_PTR) {
                                expect_fopen_count = 1;
                            }
                            expected_stream = output.second;
                            b.timestamp = timestamp.second;
                            b.pid = pid.second;
                            b.flushLevel = (utils_log_level_t)flushLevel.second;

                            b.level = (utils_log_level_t)logLevel.second;
                            if (logLevel.second <= LOG_INFO) {
                                expect_fput_count = 1;
                            }
                        } else {
                            expect_fput_count = 1;
                            if (expected_filename.size() > MAX_FILE_PATH) {
                                expected_message =
                                    "[ERROR UMF] utils_log_init: Cannot open "
                                    "output file - path too long\n";
                            }
                        }
                        helper_log_init(envVar.c_str());
                        helper_checkConfig(&b, &loggerConfig);
                    }
                }
            }
        }
    }
}

template <typename... Args> void helper_test_log(Args... args) {
    fput_count = 0;
    fflush_count = 0;
    utils_log(args...);
    EXPECT_EQ(fput_count, expect_fput_count);
    EXPECT_EQ(fflush_count, expect_fflush_count);
}

static std::string helper_log_str(int l) {
    switch (l) {
    case LOG_DEBUG:
        return "DEBUG";
    case LOG_ERROR:
        return "ERROR";
    case LOG_INFO:
        return "INFO ";
    case LOG_WARNING:
        return "WARN ";
    case LOG_FATAL:
        return "FATAL";
    default:
        ASSERT(0);
        return "";
    }
}

TEST_F(test, log_levels) {
    expected_stream = stderr;
    for (int i = LOG_DEBUG; i <= LOG_ERROR; i++) {
        for (int j = LOG_DEBUG; j <= LOG_ERROR; j++) {
            loggerConfig = {0, 0, (utils_log_level_t)i, LOG_DEBUG, stderr};
            if (i > j) {
                expect_fput_count = 0;
                expect_fflush_count = 0;
                expected_message = "";
            } else {
                expect_fput_count = 1;
                expect_fflush_count = 1;
            }
            expected_message = "[" + helper_log_str(j) + " UMF] " +
                               MOCK_FN_NAME + ": example log\n";
            helper_test_log((utils_log_level_t)j, MOCK_FN_NAME.c_str(), "%s",
                            "example log");
        }
    }
}

TEST_F(test, log_outputs) {
    std::vector<FILE *> outs = {stdout, stderr, MOCK_FILE_PTR};
    expect_fput_count = 1;
    expect_fflush_count = 1;
    expected_message = "[DEBUG UMF] " + MOCK_FN_NAME + ": example log\n";
    for (auto o : outs) {
        loggerConfig = {0, 0, LOG_DEBUG, LOG_DEBUG, o};
        expected_stream = o;
        helper_test_log(LOG_DEBUG, MOCK_FN_NAME.c_str(), "%s", "example log");
    }
}

TEST_F(test, flush_levels) {
    expected_stream = stderr;
    expect_fput_count = 1;
    for (int i = LOG_DEBUG; i <= LOG_ERROR; i++) {
        for (int j = LOG_DEBUG; j <= LOG_ERROR; j++) {
            loggerConfig = {0, 0, LOG_DEBUG, (utils_log_level_t)i, stderr};
            if (i > j) {
                expect_fflush_count = 0;
            } else {
                expect_fflush_count = 1;
            }
            expected_message = "[" + helper_log_str(j) + " UMF] " +
                               MOCK_FN_NAME + ": example log\n";
            helper_test_log((utils_log_level_t)j, MOCK_FN_NAME.c_str(), "%s",
                            "example log");
        }
    }
}

TEST_F(test, long_log) {
    expect_fput_count = 1;
    expect_fflush_count = 1;
    loggerConfig = {0, 0, LOG_DEBUG, LOG_DEBUG, stderr};
    expected_message = "[DEBUG UMF] " + MOCK_FN_NAME + ": " +
                       std::string(8189 - MOCK_FN_NAME.size(), 'x') + "\n";
    helper_test_log(LOG_DEBUG, MOCK_FN_NAME.c_str(), "%s",
                    std::string(8189 - MOCK_FN_NAME.size(), 'x').c_str());
    expected_message = "[DEBUG UMF] " + MOCK_FN_NAME + ": " +
                       std::string(8189 - MOCK_FN_NAME.size(), 'x') +
                       "[truncated...]\n";
    helper_test_log(LOG_DEBUG, MOCK_FN_NAME.c_str(), "%s",
                    std::string(8190 - MOCK_FN_NAME.size(), 'x').c_str());
}

TEST_F(test, timestamp_log) {
    expect_fput_count = 1;
    expect_fflush_count = 1;
    loggerConfig = {1, 0, LOG_DEBUG, LOG_DEBUG, stderr};
    // TODO: for now we do not check output message,
    // as it requires more sophisticated message validation (a.k.a regrex)
    expected_message = "";
    helper_test_log(LOG_DEBUG, MOCK_FN_NAME.c_str(), "%s", "example log");
}

TEST_F(test, pid_log) {
    expect_fput_count = 1;
    expect_fflush_count = 1;
    loggerConfig = {0, 1, LOG_DEBUG, LOG_DEBUG, stderr};
    // TODO: for now we do not check output message,
    // as it requires more sophisticated message validation (a.k.a regrex)
    expected_message = "";
    helper_test_log(LOG_DEBUG, MOCK_FN_NAME.c_str(), "%s", "example log");
}

TEST_F(test, log_fatal) {
    loggerConfig = {0, 0, LOG_DEBUG, LOG_DEBUG, NULL};
    expected_stream = stderr;
    expect_fput_count = 1;
    expect_fflush_count = 1;

    expected_message = "[FATAL UMF] " + MOCK_FN_NAME + ": example log\n";
    strerror_ret_static = 0;
    helper_test_log(LOG_FATAL, MOCK_FN_NAME.c_str(), "%s", "example log");
}

TEST_F(test, log_macros) {
    expected_stream = stderr;
    expect_fput_count = 1;
    expect_fflush_count = 1;
    loggerConfig = {0, 0, LOG_DEBUG, LOG_DEBUG, stderr};

    expected_message = "[DEBUG UMF] TestBody: example log\n";
    fput_count = 0;
    fflush_count = 0;
    LOG_DEBUG("example log");
    EXPECT_EQ(fput_count, expect_fput_count);
    EXPECT_EQ(fflush_count, expect_fflush_count);

    expected_message = "[INFO  UMF] TestBody: example log\n";
    fput_count = 0;
    fflush_count = 0;
    LOG_INFO("example log");
    EXPECT_EQ(fput_count, expect_fput_count);
    EXPECT_EQ(fflush_count, expect_fflush_count);

    expected_message = "[WARN  UMF] TestBody: example log\n";
    fput_count = 0;
    fflush_count = 0;
    LOG_WARN("example log");
    EXPECT_EQ(fput_count, expect_fput_count);
    EXPECT_EQ(fflush_count, expect_fflush_count);

    expected_message = "[ERROR UMF] TestBody: example log\n";
    fput_count = 0;
    fflush_count = 0;
    LOG_ERR("example log");
    EXPECT_EQ(fput_count, expect_fput_count);
    EXPECT_EQ(fflush_count, expect_fflush_count);

    expected_message = "[FATAL UMF] TestBody: example log\n";
    fput_count = 0;
    fflush_count = 0;
    LOG_FATAL("example log");
    EXPECT_EQ(fput_count, expect_fput_count);
    EXPECT_EQ(fflush_count, expect_fflush_count);
}

template <typename... Args> void helper_test_plog(Args... args) {
    fput_count = 0;
    fflush_count = 0;
    utils_plog(args...);
    EXPECT_EQ(fput_count, expect_fput_count);
    EXPECT_EQ(fflush_count, expect_fflush_count);
}

TEST_F(test, plog_basic) {
    loggerConfig = {0, 0, LOG_DEBUG, LOG_DEBUG, stderr};
    expected_stream = stderr;
    errno = 1;
    strerr = "test error";
    expect_fput_count = 1;
    expect_fflush_count = 1;

    expected_message =
        "[DEBUG UMF] " + MOCK_FN_NAME + ": example log: test error\n";
    strerror_ret_static = 1;
    helper_test_plog(LOG_DEBUG, MOCK_FN_NAME.c_str(), "%s", "example log");
    strerror_ret_static = 0;
    helper_test_plog(LOG_DEBUG, MOCK_FN_NAME.c_str(), "%s", "example log");
}

TEST_F(test, plog_invalid) {
    loggerConfig = {0, 0, LOG_DEBUG, LOG_DEBUG, stderr};
    expected_stream = stderr;
    errno = INVALID_ERRNO;
    strerr = "test error";
    expect_fput_count = 1;
    expect_fflush_count = 1;

    expected_message =
        "[DEBUG UMF] " + MOCK_FN_NAME + ": example log: unknown error\n";
    strerror_ret_static = 1;
    helper_test_plog(LOG_DEBUG, MOCK_FN_NAME.c_str(), "%s", "example log");
    strerror_ret_static = 0;
    helper_test_plog(LOG_DEBUG, MOCK_FN_NAME.c_str(), "%s", "example log");
}

TEST_F(test, plog_long_message) {
    loggerConfig = {0, 0, LOG_DEBUG, LOG_DEBUG, stderr};
    expected_stream = stderr;
    expect_fput_count = 1;
    expect_fflush_count = 1;
    strerror_ret_static = 0;
    strerr = "test error";
    errno = 1;

    expected_message = "[DEBUG UMF] " + MOCK_FN_NAME + ": " +
                       std::string(8178 - MOCK_FN_NAME.length(), 'x') +
                       ": test err" + "o[truncated...]\n";
    helper_test_plog(LOG_DEBUG, MOCK_FN_NAME.c_str(), "%s",
                     std::string(8178 - MOCK_FN_NAME.length(), 'x').c_str());
    expected_message = "[DEBUG UMF] " + MOCK_FN_NAME + ": " +
                       std::string(8189 - MOCK_FN_NAME.length(), 'x') +
                       "[truncated...]\n";
    helper_test_plog(LOG_DEBUG, MOCK_FN_NAME.c_str(), "%s",
                     std::string(8190 - MOCK_FN_NAME.length(), 'x').c_str());
}

TEST_F(test, plog_long_error) {
    loggerConfig = {0, 0, LOG_DEBUG, LOG_DEBUG, stderr};
    expected_stream = stderr;
    expect_fput_count = 1;
    expect_fflush_count = 1;
    strerror_ret_static = 0;
    std::string tmp = std::string(2000, 'x');
    strerr = tmp.c_str();
    errno = 1;
#ifdef WIN32
    /* On windows limit is shorter, and there is no truncated detection*/
    expected_message = "[DEBUG UMF] " + MOCK_FN_NAME +
                       ": example log: " + std::string(79, 'x') + "\n";
#else
    expected_message = "[DEBUG UMF] " + MOCK_FN_NAME +
                       ": example log: " + std::string(1023, 'x') +
                       "[truncated...]\n";
#endif
    strerror_ret_static = 0;
    helper_test_plog(LOG_DEBUG, MOCK_FN_NAME.c_str(), "%s", "example log");
    strerr = NULL; // do not use tmp.c_str() beyond its scope
}

TEST_F(test, log_pmacros) {
    expected_stream = stderr;
    expect_fput_count = 1;
    expect_fflush_count = 1;
    loggerConfig = {0, 0, LOG_DEBUG, LOG_DEBUG, stderr};
    errno = 1;
    strerr = "test error";

    expected_message = "[DEBUG UMF] TestBody: example log: test error\n";
    fput_count = 0;
    fflush_count = 0;
    LOG_PDEBUG("example log");
    EXPECT_EQ(fput_count, expect_fput_count);
    EXPECT_EQ(fflush_count, expect_fflush_count);

    expected_message = "[INFO  UMF] TestBody: example log: test error\n";
    fput_count = 0;
    fflush_count = 0;
    LOG_PINFO("example log");
    EXPECT_EQ(fput_count, expect_fput_count);
    EXPECT_EQ(fflush_count, expect_fflush_count);

    expected_message = "[WARN  UMF] TestBody: example log: test error\n";
    fput_count = 0;
    fflush_count = 0;
    LOG_PWARN("example log");
    EXPECT_EQ(fput_count, expect_fput_count);
    EXPECT_EQ(fflush_count, expect_fflush_count);

    expected_message = "[ERROR UMF] TestBody: example log: test error\n";
    fput_count = 0;
    fflush_count = 0;
    LOG_PERR("example log");
    EXPECT_EQ(fput_count, expect_fput_count);
    EXPECT_EQ(fflush_count, expect_fflush_count);

    expected_message = "[FATAL UMF] TestBody: example log: test error\n";
    fput_count = 0;
    fflush_count = 0;
    LOG_PFATAL("example log");
    EXPECT_EQ(fput_count, expect_fput_count);
    EXPECT_EQ(fflush_count, expect_fflush_count);
}
