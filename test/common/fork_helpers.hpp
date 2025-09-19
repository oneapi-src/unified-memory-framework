/*
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#pragma once

#include "umf.h"
#include <gtest/gtest.h>

#include <type_traits>
#include <utility>

#ifndef _WIN32
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace umf_test {

constexpr int ForkedTestSuccess = 0;
constexpr int ForkedTestFailure = 1;
constexpr int ForkedTestSkip = 77;

template <typename Func> void run_in_fork(Func &&func) {
#ifndef _WIN32
    static_assert(std::is_invocable_r_v<void, Func &&>,
                  "run_in_fork requires a void-returning callable");

    pid_t pid = fork();
    ASSERT_NE(pid, -1) << "fork failed";

    if (pid == 0) {
        std::forward<Func>(func)();

        auto *unit = ::testing::UnitTest::GetInstance();
        const ::testing::TestInfo *info =
            unit ? unit->current_test_info() : nullptr;
        const ::testing::TestResult *result = info ? info->result() : nullptr;

        if (result != nullptr) {
            if (result->Skipped()) {
                _exit(ForkedTestSkip);
            }
            if (result->Failed()) {
                _exit(ForkedTestFailure);
            }
        }
        umfTearDown(); // exit not call destructor so we need to call it manually
        _exit(ForkedTestSuccess);
    }

    int status = 0;
    ASSERT_EQ(waitpid(pid, &status, 0), pid) << "waitpid failed";

    if (!WIFEXITED(status)) {
        FAIL() << "Forked test terminated abnormally.";
    }

    int exit_code = WEXITSTATUS(status);
    if (exit_code == ForkedTestSkip) {
        GTEST_SKIP() << "Forked test body requested skip.";
    }

    ASSERT_EQ(exit_code, ForkedTestSuccess)
        << "Forked test exited with code " << exit_code;
#else
    (void)func;
    GTEST_SKIP() << "Fork-based tests are not supported on Windows.";
#endif
}

} // namespace umf_test
