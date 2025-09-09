/*
 *
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <string>
#include <vector>
#ifdef _WIN32
#include <process.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <umf.h>
#include <umf/base.h>
#include <umf/experimental/ctl.h>

#include "../common/base.hpp"
#include "gtest/gtest.h"

using namespace umf_test;

#ifndef CTL_ENV_APP
#define CTL_ENV_APP "./ctl_env_app"
#endif

#ifndef CTL_CONF_FILE_DIR
#define CTL_CONF_FILE_DIR "./ctl"
#endif

void set_env(std::pair<const std::string, const std::string> env) {
    const auto &name = env.first;
    const auto &value = env.second;

    if (name.empty()) {
        return;
    }
#ifdef _WIN32
    _putenv_s(name.c_str(), value.c_str());
#else
    setenv(name.c_str(), value.c_str(), 1);
#endif
}

static void run_case(
    const std::vector<std::pair<const std::string, const std::string>> &env,
    const std::vector<std::string> &args) {
    for (const auto &e : env) {
        set_env(e);
    }

#ifdef _WIN32
    std::vector<const char *> cargs;
    cargs.push_back(CTL_ENV_APP);
    for (const auto &s : args) {
        cargs.push_back(s.c_str());
    }

    cargs.push_back(nullptr);
    intptr_t status = _spawnv(_P_WAIT, CTL_ENV_APP, cargs.data());
    ASSERT_EQ(status, 0);
#else
    pid_t pid = fork();
    if (pid == 0) {
        std::vector<char *> cargs;
        cargs.push_back(const_cast<char *>(CTL_ENV_APP));
        for (const auto &s : args) {
            cargs.push_back(const_cast<char *>(s.c_str()));
        }
        cargs.push_back(nullptr);
        execv(CTL_ENV_APP, cargs.data());
        std::cerr << "Failed to execute " << CTL_ENV_APP << std::endl;
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    ASSERT_EQ(status, 0);
#endif
    for (const auto &e : env) {
        set_env({e.first, ""}); // Clear the environment variable
    }
}

TEST_F(test, ctl_env_defaults) {
    run_case(
        {{"UMF_CONF", "umf.pool.default.test_pool.opt_one=test_value"}},
        {"env_defaults", "umf.pool.default.test_pool.opt_one", "test_value"});

    run_case({{"UMF_CONF", "umf.pool.default.test_pool.opt_one=second"}},
             {"env_defaults", "umf.pool.default.test_pool.opt_one", "second"});
}

TEST_F(test, ctl_env_file) {
    std::string cfg1 = CTL_CONF_FILE_DIR "/ctl_env_config1.cfg";
    std::string cfg2 = CTL_CONF_FILE_DIR "/ctl_env_config2.cfg";

    run_case({{"UMF_CONF_FILE", cfg1}},
             {"env_defaults", "umf.pool.default.test_pool.opt_one",
              "opt_one_value1"});

    run_case({{"UMF_CONF_FILE", cfg2}},
             {"env_defaults", "umf.pool.default.test_pool.opt_one",
              "opt_one_value2", "umf.pool.default.test_pool.opt_two",
              "opt_two_value2"});
}

TEST_F(test, ctl_env_plus_file) {
    std::string cfg = CTL_CONF_FILE_DIR "/ctl_env_config2.cfg";

    // it is expected that configuration from file will override configuration from environment variable
    run_case({{"UMF_CONF_FILE", cfg},
              {"UMF_CONF", "umf.pool.default.test_pool.opt_one=first;umf.pool."
                           "default.test_pool.opt_three=second"}},
             {"env_defaults", "umf.pool.default.test_pool.opt_one",
              "opt_one_value2", "umf.pool.default.test_pool.opt_two",
              "opt_two_value2", "umf.pool.default.test_pool.opt_three",
              "second"});
}

TEST_F(test, ctl_env_logger) {
    run_case({{"UMF_CONF", "umf.logger.output=stdout;umf.logger.level=0"}},
             {"logger", "stdout", "0"});
}
