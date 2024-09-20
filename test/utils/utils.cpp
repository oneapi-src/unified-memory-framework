// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "base.hpp"
#include "test_helpers.h"
#include "utils/utils_common.h"

using umf_test::test;

TEST_F(test, utils_parse_var) {
    EXPECT_FALSE(utils_parse_var("", "test1", 0));

    EXPECT_TRUE(utils_parse_var("test1;test2;test3;test4", "test1", 0));
    EXPECT_TRUE(utils_parse_var("test1;test2;test3;test4", "test2", 0));
    EXPECT_TRUE(utils_parse_var("test1;test2;test3;test4", "test3", 0));
    EXPECT_TRUE(utils_parse_var("test1;test2;test3;test4", "test4", 0));

    EXPECT_TRUE(utils_parse_var(";test1;test2;test3;test4;", "test1", 0));
    EXPECT_TRUE(utils_parse_var(";test1;test2;test3;test4;", "test2", 0));
    EXPECT_TRUE(utils_parse_var(";test1;test2;test3;test4;", "test3", 0));
    EXPECT_TRUE(utils_parse_var(";test1;test2;test3;test4;", "test4", 0));

    EXPECT_FALSE(utils_parse_var("test1;test2;test3;test4", "test5", 0));

    EXPECT_FALSE(utils_parse_var("test1test2test3test4", "test1", 0));
    EXPECT_FALSE(utils_parse_var("test1test2test3test4", "test2", 0));
    EXPECT_FALSE(utils_parse_var("test1test2test3test4", "test3", 0));
    EXPECT_FALSE(utils_parse_var("test1test2test3test4", "test4", 0));

    EXPECT_FALSE(utils_parse_var("test1:test2;test3:test4", "test1", 0));
    EXPECT_FALSE(utils_parse_var("test1:test2;test3:test4", "test2", 0));
    EXPECT_FALSE(utils_parse_var("test1:test2;test3:test4", "test3", 0));
    EXPECT_FALSE(utils_parse_var("test1:test2;test3:test4", "test4", 0));

    EXPECT_TRUE(utils_parse_var("test1:test2;test3:test4", "test1:test2", 0));
    EXPECT_TRUE(utils_parse_var("test1:test2;test3:test4", "test3:test4", 0));
    EXPECT_FALSE(utils_parse_var("test1:test2;test3:test4", "test2:test3'", 0));

    EXPECT_TRUE(
        utils_parse_var("test1;;test2;invalid;test3;;;test4", "test1", 0));
    EXPECT_TRUE(
        utils_parse_var("test1;;test2;invalid;test3;;;test4", "test2", 0));
    EXPECT_TRUE(
        utils_parse_var("test1;;test2;invalid;test3;;;test4", "test3", 0));
    EXPECT_TRUE(
        utils_parse_var("test1;;test2;invalid;test3;;;test4", "test4", 0));

    const char *arg;
    EXPECT_FALSE(utils_parse_var("test1;test2;test3;test4", "test1", &arg));
    EXPECT_FALSE(utils_parse_var("test1;test2;test3;test4", "test2", &arg));
    EXPECT_FALSE(utils_parse_var("test1;test2;test3;test4", "test3", &arg));
    EXPECT_FALSE(utils_parse_var("test1;test2;test3;test4", "test4", &arg));

    EXPECT_TRUE(utils_parse_var("test1,abc;test2;test3;test4", "test1", &arg));
    EXPECT_TRUE(utils_parse_var("test1;test2,abc;test3;test4", "test2", &arg));
    EXPECT_TRUE(utils_parse_var("test1;test2;test3,abc;test4", "test3", &arg));
    EXPECT_TRUE(utils_parse_var("test1;test2;test3;test4,abc", "test4", &arg));
}
