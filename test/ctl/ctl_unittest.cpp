/*
 *
 * Copyright (C) 2024-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "../common/base.hpp"
#include "ctl/ctl_debug.h"
#include "ctl/ctl_internal.h"

using namespace umf_test;

void get_test_va_list(va_list *a, ...) { va_start(*a, a); }

TEST_F(test, ctl_debug_read_from_string) {
    initialize_debug_ctl();
    auto ctl_handler = get_debug_ctl();
    va_list empty_args;
    get_test_va_list(&empty_args);
    ASSERT_EQ(ctl_load_config_from_string(ctl_handler, NULL,
                                          "debug.heap.alloc_pattern=1"),
              UMF_RESULT_SUCCESS);

    int value = 0;
    ctl_query(ctl_handler, NULL, CTL_QUERY_PROGRAMMATIC,
              "debug.heap.alloc_pattern", CTL_QUERY_READ, &value, sizeof(value),
              empty_args);
    ASSERT_EQ(value, 1);

    // Test setting alloc_pattern to 2
    ASSERT_EQ(ctl_load_config_from_string(ctl_handler, NULL,
                                          "debug.heap.alloc_pattern=2"),
              UMF_RESULT_SUCCESS);
    ctl_query(ctl_handler, NULL, CTL_QUERY_PROGRAMMATIC,
              "debug.heap.alloc_pattern", CTL_QUERY_READ, &value, sizeof(value),
              empty_args);
    ASSERT_EQ(value, 2);

    // Test setting alloc_pattern to 0
    ASSERT_EQ(ctl_load_config_from_string(ctl_handler, NULL,
                                          "debug.heap.alloc_pattern=0"),
              UMF_RESULT_SUCCESS);
    ctl_query(ctl_handler, NULL, CTL_QUERY_PROGRAMMATIC,
              "debug.heap.alloc_pattern", CTL_QUERY_READ, &value, sizeof(value),
              empty_args);
    ASSERT_EQ(value, 0);

    // Negative test: non-existent configuration
    ASSERT_NE(ctl_query(ctl_handler, NULL, CTL_QUERY_PROGRAMMATIC,
                        "debug.heap.non_existent", CTL_QUERY_READ, &value,
                        sizeof(value), empty_args),
              UMF_RESULT_SUCCESS);

    // Negative test: invalid path
    ASSERT_NE(ctl_query(ctl_handler, NULL, CTL_QUERY_PROGRAMMATIC,
                        "invalid.path.alloc_pattern", CTL_QUERY_READ, &value,
                        sizeof(value), empty_args),
              UMF_RESULT_SUCCESS);
    va_end(empty_args);
}

int ctl_config_write_to_file(const char *filename, const char *data) {
    FILE *file = fopen(filename == NULL ? "config.txt" : filename, "w+");
    if (file == NULL) {
        return -1;
    }
    fputs(data, file);
    fclose(file);
    return 0;
}

TEST_F(test, ctl_debug_read_from_file) {
    va_list empty_args;
    get_test_va_list(&empty_args);
#ifndef _WIN32
    ASSERT_EQ(ctl_config_write_to_file(
                  "config.txt", "debug.heap.alloc_pattern=321;\ndebug.heap."
                                "enable_logging=1;\ndebug.heap.log_level=5;\n"),
              0);
    initialize_debug_ctl();
    auto ctl_handler = get_debug_ctl();
    ASSERT_EQ(ctl_load_config_from_file(ctl_handler, NULL, "config.txt"),
              UMF_RESULT_SUCCESS);

    int value = 0;
    ctl_query(ctl_handler, NULL, CTL_QUERY_PROGRAMMATIC,
              "debug.heap.alloc_pattern", CTL_QUERY_READ, &value, 0,
              empty_args);
    ASSERT_EQ(value, 321);

    value = 0;
    ctl_query(ctl_handler, NULL, CTL_QUERY_PROGRAMMATIC, "debug.heap.log_level",
              CTL_QUERY_READ, &value, 0, empty_args);
    ASSERT_EQ(value, 5);

    value = 0;
    ctl_query(ctl_handler, NULL, CTL_QUERY_PROGRAMMATIC,
              "debug.heap.enable_logging", CTL_QUERY_READ, &value, 0,
              empty_args);
    ASSERT_EQ(value, 1);
#endif
    va_end(empty_args);
}

void ctl_helper(struct ctl *ctl_handler, const char *name, int *out, ...) {
    va_list args;
    va_start(args, out);
    umf_result_t ret = ctl_query(ctl_handler, NULL, CTL_QUERY_PROGRAMMATIC,
                                 name, CTL_QUERY_READ, out, sizeof(*out), args);
    va_end(args);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
}

TEST_F(test, ctl_debug_node_arg) {
    initialize_debug_ctl();
    auto ctl_handler = get_debug_ctl();
    int arg;
    va_list empty_args;
    get_test_va_list(&empty_args);

    // Following ctl_query calls are expected to return a int value
    // passed as a parameter inside of the name
    umf_result_t ret = ctl_query(ctl_handler, NULL, CTL_QUERY_PROGRAMMATIC,
                                 "debug.arg_test.972.arg_value", CTL_QUERY_READ,
                                 &arg, sizeof(arg), empty_args);

    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(arg, 972);

    ret = ctl_query(ctl_handler, NULL, CTL_QUERY_PROGRAMMATIC,
                    "debug.arg_test.1410.arg_value", CTL_QUERY_READ, &arg,
                    sizeof(arg), empty_args);

    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(arg, 1410);

    ret = ctl_query(ctl_handler, NULL, CTL_QUERY_PROGRAMMATIC,
                    "debug.arg_test_final.1514", CTL_QUERY_READ, &arg,
                    sizeof(arg), empty_args);

    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(arg, 1514);

    ret = ctl_query(ctl_handler, NULL, CTL_QUERY_PROGRAMMATIC,
                    "debug.arg_test_final.1621", CTL_QUERY_READ, &arg,
                    sizeof(arg), empty_args);

    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(arg, 1621);

    ASSERT_NO_FATAL_FAILURE(
        ctl_helper(ctl_handler, "debug.arg_test.{}.arg_value", &arg, 1651));

    ASSERT_EQ(arg, 1651);

    ASSERT_NO_FATAL_FAILURE(ctl_helper(ctl_handler, "debug.{}.{}.arg_value",
                                       &arg, "arg_test", 1655));

    ASSERT_EQ(arg, 1655);

    ASSERT_NO_FATAL_FAILURE(ctl_helper(ctl_handler, "{}.{}.{}.{}", &arg,
                                       "debug", "arg_test", 1920, "arg_value"));

    ASSERT_EQ(arg, 1920);
    va_end(empty_args);
}

TEST_F(test, ctl_debug_node_arg_invalid) {
    initialize_debug_ctl();
    auto ctl_handler = get_debug_ctl();
    int arg;
    va_list empty_args;
    get_test_va_list(&empty_args);

    umf_result_t ret = ctl_query(ctl_handler, NULL, CTL_QUERY_PROGRAMMATIC,
                                 "debug.arg_test.42", CTL_QUERY_READ, &arg,
                                 sizeof(arg), empty_args);

    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = ctl_query(ctl_handler, NULL, CTL_QUERY_PROGRAMMATIC,
                    "debug.arg_test.arg_value", CTL_QUERY_READ, &arg,
                    sizeof(arg), empty_args);

    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = ctl_query(ctl_handler, NULL, CTL_QUERY_PROGRAMMATIC,
                    "debug.arg_test.wrong_type.arg_value", CTL_QUERY_READ, &arg,
                    sizeof(arg), empty_args);

    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    va_end(empty_args);
}
