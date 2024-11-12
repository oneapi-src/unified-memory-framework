// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "base.hpp"
#include "utils/utils_common.h"

using umf_test::test;
TEST_F(test, utils_translate_mem_visibility_flag) {
    umf_memory_visibility_t in_flag = static_cast<umf_memory_visibility_t>(0);
    unsigned out_flag;
    auto ret = utils_translate_mem_visibility_flag(in_flag, &out_flag);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_F(test, utils_shm_open_invalid_args) {
    auto ret = utils_shm_open(NULL);
    EXPECT_EQ(ret, -1);

    ret = utils_shm_open("invalid_path");
    EXPECT_EQ(ret, -1);
}

TEST_F(test, utils_get_file_size_invalid_args) {
    size_t size;
    auto ret = utils_get_file_size(0xffffff, &size);
    EXPECT_EQ(ret, -1);

    int fd = utils_create_anonymous_fd();
    ASSERT_GE(fd, 0);

    // Explicit condition for coverity
    if (fd >= 0) {
        ret = utils_get_file_size(fd, &size);
        EXPECT_EQ(ret, 0);
        EXPECT_EQ(size, 0);
    }
}

TEST_F(test, utils_set_file_size_invalid_args) {
    auto ret = utils_set_file_size(0xffffff, 256);
    EXPECT_EQ(ret, -1);
}

TEST_F(test, utils_shm_create_invalid_args) {
    auto ret = utils_shm_create(NULL, 0);
    EXPECT_EQ(ret, -1);

    ret = utils_shm_create("", 256);
    EXPECT_EQ(ret, -1);

    // Ensure that a valid size results in a success
    ret = utils_shm_create("/abc", 256);
    EXPECT_GE(ret, 0);

    ret = utils_shm_create("/abc", -1);
    EXPECT_EQ(ret, -1);
}
