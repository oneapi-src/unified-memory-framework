// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <sys/mman.h>

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

TEST_F(test, utils_get_size_threshold) {
    // Expected input to utils_get_size_threshold():
    // char *str_threshold = utils_env_var_get_str("UMF_PROXY", "size.threshold=");

    // positive tests
    EXPECT_EQ(utils_get_size_threshold((char *)"size.threshold=111"), 111);
    EXPECT_EQ(utils_get_size_threshold((char *)"size.threshold=222;abcd"), 222);
    EXPECT_EQ(utils_get_size_threshold((char *)"size.threshold=333;var=value"),
              333);
    // LONG_MAX = 9223372036854775807
    EXPECT_EQ(utils_get_size_threshold(
                  (char *)"size.threshold=9223372036854775807;var=value"),
              9223372036854775807);

    // negative tests
    EXPECT_EQ(utils_get_size_threshold(NULL), 0);
    EXPECT_EQ(utils_get_size_threshold((char *)"size.threshold="), -1);
    EXPECT_EQ(utils_get_size_threshold((char *)"size.threshold=abc"), -1);
    EXPECT_EQ(utils_get_size_threshold((char *)"size.threshold=-111"), -1);
}

TEST_F(test, utils_errno_to_umf_result) {
    EXPECT_EQ(utils_errno_to_umf_result(EBADF),
              UMF_RESULT_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(utils_errno_to_umf_result(EINVAL),
              UMF_RESULT_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(utils_errno_to_umf_result(ESRCH),
              UMF_RESULT_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(utils_errno_to_umf_result(EPERM),
              UMF_RESULT_ERROR_INVALID_ARGUMENT);

    EXPECT_EQ(utils_errno_to_umf_result(EMFILE),
              UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY);
    EXPECT_EQ(utils_errno_to_umf_result(ENOMEM),
              UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY);

    EXPECT_EQ(utils_errno_to_umf_result(ENODEV),
              UMF_RESULT_ERROR_NOT_SUPPORTED);
    EXPECT_EQ(utils_errno_to_umf_result(ENOSYS),
              UMF_RESULT_ERROR_NOT_SUPPORTED);
    EXPECT_EQ(utils_errno_to_umf_result(ENOTSUP),
              UMF_RESULT_ERROR_NOT_SUPPORTED);

    EXPECT_EQ(utils_errno_to_umf_result(E2BIG), UMF_RESULT_ERROR_UNKNOWN);
}

TEST_F(test, utils_translate_mem_protection_flags) {
    umf_result_t umf_result;
    unsigned out_protection;

    umf_result = utils_translate_mem_protection_flags(UMF_PROTECTION_NONE,
                                                      &out_protection);
    EXPECT_EQ(umf_result, UMF_RESULT_SUCCESS);
    EXPECT_EQ(out_protection, PROT_NONE);

    umf_result = utils_translate_mem_protection_flags(UMF_PROTECTION_READ,
                                                      &out_protection);
    EXPECT_EQ(umf_result, UMF_RESULT_SUCCESS);
    EXPECT_EQ(out_protection, PROT_READ);

    umf_result = utils_translate_mem_protection_flags(UMF_PROTECTION_WRITE,
                                                      &out_protection);
    EXPECT_EQ(umf_result, UMF_RESULT_SUCCESS);
    EXPECT_EQ(out_protection, PROT_WRITE);

    umf_result = utils_translate_mem_protection_flags(UMF_PROTECTION_EXEC,
                                                      &out_protection);
    EXPECT_EQ(umf_result, UMF_RESULT_SUCCESS);
    EXPECT_EQ(out_protection, PROT_EXEC);

    umf_result = utils_translate_mem_protection_flags(
        UMF_PROTECTION_READ | UMF_PROTECTION_WRITE, &out_protection);
    EXPECT_EQ(umf_result, UMF_RESULT_SUCCESS);
    EXPECT_EQ(out_protection, PROT_READ | PROT_WRITE);

    umf_result = utils_translate_mem_protection_flags(
        UMF_PROTECTION_READ | UMF_PROTECTION_WRITE | UMF_PROTECTION_EXEC,
        &out_protection);
    EXPECT_EQ(umf_result, UMF_RESULT_SUCCESS);
    EXPECT_EQ(out_protection, PROT_READ | PROT_WRITE | PROT_EXEC);

    umf_result = utils_translate_mem_protection_flags(
        UMF_PROTECTION_READ | UMF_PROTECTION_EXEC, &out_protection);
    EXPECT_EQ(umf_result, UMF_RESULT_SUCCESS);
    EXPECT_EQ(out_protection, PROT_READ | PROT_EXEC);

    umf_result = utils_translate_mem_protection_flags(
        UMF_PROTECTION_WRITE | UMF_PROTECTION_EXEC, &out_protection);
    EXPECT_EQ(umf_result, UMF_RESULT_SUCCESS);
    EXPECT_EQ(out_protection, PROT_WRITE | PROT_EXEC);

    // see https://github.com/oneapi-src/unified-memory-framework/issues/923
    out_protection = 0;
    umf_result = utils_translate_mem_protection_flags(
        0xFFFF & ~(((UMF_PROTECTION_MAX - 1) << 1) - 1), &out_protection);
    EXPECT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(out_protection, 0);
}

TEST_F(test, utils_translate_purge_advise) {
    EXPECT_EQ(utils_translate_purge_advise(UMF_PURGE_LAZY), MADV_FREE);
    EXPECT_EQ(utils_translate_purge_advise(UMF_PURGE_FORCE), MADV_DONTNEED);
    EXPECT_EQ(utils_translate_purge_advise(UMF_PURGE_MAX), -1);
}

TEST_F(test, utils_open) {
    EXPECT_EQ(utils_devdax_open(NULL), -1);
    EXPECT_EQ(utils_file_open(NULL), -1);
    EXPECT_EQ(utils_file_open_or_create(NULL), -1);
}
