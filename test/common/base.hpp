/*
 *
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_TEST_BASE_HPP
#define UMF_TEST_BASE_HPP 1

#include <gtest/gtest.h>

namespace umf_test {

#define IS_SKIPPED_OR_FAILED() (HasFatalFailure() || IsSkipped())

#define NOEXCEPT_COND(cond, val, expected_val)                                                                   \
    try {                                                                                                        \
        cond(val, expected_val);                                                                                 \
    } catch (                                                                                                    \
        ...) { /* Silencing possible GoogleTestFailureException throw when gtest flag throw_on_failure is set */ \
    }

#define EXPECT_EQ_NOEXCEPT(val, expected_val)                                  \
    NOEXCEPT_COND(EXPECT_EQ, val, expected_val)

#define EXPECT_NE_NOEXCEPT(val, expected_val)                                  \
    NOEXCEPT_COND(EXPECT_NE, val, expected_val)

struct test : ::testing::Test {
    void SetUp() override { ::testing::Test::SetUp(); }
    void TearDown() override { ::testing::Test::TearDown(); }
};

template <typename T> T generateArg() { return T{}; }

// returns Ret (*f)(void) that calls the original function
// with all arguments created by calling generateArg()
template <typename Ret, typename... Args>
std::function<Ret(void)> withGeneratedArgs(Ret (*f)(Args...)) {
    return [f]() {
        auto args = std::apply(
            [](auto... x) {
                return std::make_tuple(generateArg<decltype(x)>()...);
            },
            std::tuple<Args...>{});
        return std::apply(f, std::move(args));
    };
}

const size_t KB = 1024;
const size_t MB = 1024 * KB;

} // namespace umf_test

#endif /* UMF_TEST_BASE_HPP */
