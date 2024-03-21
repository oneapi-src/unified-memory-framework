// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "base.hpp"
#include "test_helpers.h"

#define MOCK_FILE_PTR (FILE *)0xBADBEEF
std::string expected_filename;
int expect_fopen_count = 0;
int fopen_count = 0;

FILE *mock_fopen(const char *filename, const char *mode) {
    fopen_count++;
    EXPECT_STREQ(filename, expected_filename.c_str());
    EXPECT_STREQ(mode, "w");
    return MOCK_FILE_PTR;
}

std::string expected_message = "";
FILE *expected_stream;
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

extern "C" {

const char *env_variable = "";
#define fopen(A, B) mock_fopen(A, B)
#define fputs(A, B) mock_fputs(A, B)
#define fflush(A) mock_fflush(A)
#define util_env_var(A, B, C) mock_util_env_var(A, B, C)

//getenv returns 'char *' not 'const char *' so we need explicit cast to drop const
#define getenv(X) strstr(X, "UMF_LOG") ? (char *)env_variable : getenv(X)
#include "utils/utils_log.c"
#undef util_env_var
#undef fopen
#undef fputs
#undef fflush
}
using umf_test::test;

void helper_log_init(const char *var) {
    env_variable = var;
    fopen_count = 0;
    fput_count = 0;
    util_log_init();
    env_variable = NULL;
    EXPECT_EQ(fopen_count, expect_fopen_count);
    EXPECT_EQ(fput_count, expect_fput_count);
}

void helper_checkConfig(util_log_config_t *expected, util_log_config_t *is) {
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
    util_log_config_t b = loggerConfig;
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
    expected_message = "[ERROR UMF] Cannot open output file - path too long\n";
    std::string test_env = "output:file," + std::string(300, 'x');
    helper_log_init(test_env.c_str());
}

TEST_F(test, parseEnv) {
    util_log_config_t b = loggerConfig;
    expected_message = "";

    std::vector<std::pair<std::string, int>> logLevels = {
        {"level:debug", LOG_DEBUG},   {"level:info", LOG_INFO},
        {"level:invalid", LOG_ERROR}, {"level:warning", LOG_WARNING},
        {"level:error", LOG_ERROR},   {"", LOG_ERROR}};

    std::vector<std::pair<std::string, int>> flushLevels = {
        {"flush:debug", LOG_DEBUG}, {"flush:invalid", LOG_ERROR},
        {"flush:info", LOG_INFO},   {"flush:warning", LOG_WARNING},
        {"flush:error", LOG_ERROR}, {"", LOG_ERROR}};

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
                            b.flushLevel = (util_log_level_t)flushLevel.second;

                            b.level = (util_log_level_t)logLevel.second;
                            if (logLevel.second <= LOG_INFO) {
                                expect_fput_count = 1;
                            }
                        } else {
                            expect_fput_count = 1;
                            if (expected_filename.size() > MAX_FILE_PATH) {
                                expected_message =
                                    "[ERROR UMF] Cannot open output file - "
                                    "path too long\n";
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
    util_log(args...);
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
    default:
        ASSERT(0);
        return "";
    }
}

TEST_F(test, log_levels) {
    expected_stream = stderr;
    for (int i = LOG_DEBUG; i <= LOG_ERROR; i++) {
        for (int j = LOG_DEBUG; j <= LOG_ERROR; j++) {
            loggerConfig = {0, 0, (util_log_level_t)i, LOG_DEBUG, stderr};
            if (i > j) {
                expect_fput_count = 0;
                expect_fflush_count = 0;
                expected_message = "";
            } else {
                expect_fput_count = 1;
                expect_fflush_count = 1;
            }
            expected_message = "[" + helper_log_str(j) + " UMF] example log\n";
            helper_test_log((util_log_level_t)j, "%s", "example log");
        }
    }
}

TEST_F(test, log_outputs) {
    std::vector<FILE *> outs = {stdout, stderr, MOCK_FILE_PTR};
    expect_fput_count = 1;
    expect_fflush_count = 1;
    expected_message = "[DEBUG UMF] example log\n";
    for (auto o : outs) {
        loggerConfig = {0, 0, LOG_DEBUG, LOG_DEBUG, o};
        expected_stream = o;
        helper_test_log(LOG_DEBUG, "%s", "example log");
    }
}

TEST_F(test, flush_levels) {
    expected_stream = stderr;
    expect_fput_count = 1;
    for (int i = LOG_DEBUG; i <= LOG_ERROR; i++) {
        for (int j = LOG_DEBUG; j <= LOG_ERROR; j++) {
            loggerConfig = {0, 0, LOG_DEBUG, (util_log_level_t)i, stderr};
            if (i > j) {
                expect_fflush_count = 0;
            } else {
                expect_fflush_count = 1;
            }
            expected_message = "[" + helper_log_str(j) + " UMF] example log\n";
            helper_test_log((util_log_level_t)j, "%s", "example log");
        }
    }
}

TEST_F(test, long_log) {
    expect_fput_count = 1;
    expect_fflush_count = 1;
    loggerConfig = {0, 0, LOG_DEBUG, LOG_DEBUG, stderr};
    expected_message = "[DEBUG UMF] " + std::string(8191, 'x') + "\n";
    helper_test_log(LOG_DEBUG, "%s", std::string(8191, 'x').c_str());
    expected_message =
        "[DEBUG UMF] " + std::string(8191, 'x') + TRUNCATED_STR + "\n";
    helper_test_log(LOG_DEBUG, "%s", std::string(8192, 'x').c_str());
}

TEST_F(test, timestamp_log) {
    expect_fput_count = 1;
    expect_fflush_count = 1;
    loggerConfig = {1, 0, LOG_DEBUG, LOG_DEBUG, stderr};
    // TODO: for now we do not check output message,
    // as it requires more sophisticated message validation (a.k.a regrex)
    expected_message = "";
    helper_test_log(LOG_DEBUG, "%s", "example log");
}

TEST_F(test, pid_log) {
    expect_fput_count = 1;
    expect_fflush_count = 1;
    loggerConfig = {0, 1, LOG_DEBUG, LOG_DEBUG, stderr};
    // TODO: for now we do not check output message,
    // as it requires more sophisticated message validation (a.k.a regrex)
    expected_message = "";
    helper_test_log(LOG_DEBUG, "%s", "example log");
}

TEST_F(test, log_macros) {
    expected_stream = stderr;
    expect_fput_count = 1;
    expect_fflush_count = 1;
    loggerConfig = {0, 0, LOG_DEBUG, LOG_DEBUG, stderr};

    expected_message = "[DEBUG UMF] example log\n";
    fput_count = 0;
    fflush_count = 0;
    LOG_DEBUG("example log");
    EXPECT_EQ(fput_count, expect_fput_count);
    EXPECT_EQ(fflush_count, expect_fflush_count);

    expected_message = "[INFO  UMF] example log\n";
    fput_count = 0;
    fflush_count = 0;
    LOG_INFO("example log");
    EXPECT_EQ(fput_count, expect_fput_count);
    EXPECT_EQ(fflush_count, expect_fflush_count);

    expected_message = "[WARN  UMF] example log\n";
    fput_count = 0;
    fflush_count = 0;
    LOG_WARN("example log");
    EXPECT_EQ(fput_count, expect_fput_count);
    EXPECT_EQ(fflush_count, expect_fflush_count);

    expected_message = "[ERROR UMF] example log\n";
    fput_count = 0;
    fflush_count = 0;
    LOG_ERR("example log");
    EXPECT_EQ(fput_count, expect_fput_count);
    EXPECT_EQ(fflush_count, expect_fflush_count);
}

template <typename... Args> void helper_test_fprintf(Args... args) {
    fput_count = 0;
    util_fprintf(args...);
    EXPECT_EQ(fput_count, expect_fput_count);
}

TEST_F(test, long_print) {
    expect_fput_count = 1;
    expected_message = std::string(8191, 'x');
    expected_stream = stderr;
    helper_test_fprintf(stderr, "%s", std::string(8191, 'x').c_str());
    expected_message = std::string(8191, 'x') + TRUNCATED_STR;
    helper_test_fprintf(stderr, "%s", std::string(8192, 'x').c_str());
}
