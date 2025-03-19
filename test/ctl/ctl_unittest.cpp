/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "../common/base.hpp"
#include "ctl/ctl.h"
#include "ctl/ctl_debug.h"

using namespace umf_test;

TEST_F(test, ctl_debug_read_from_string) {
    initialize_debug_ctl();
    auto ctl_handler = get_debug_ctl();
    ctl_load_config_from_string(ctl_handler, NULL,
                                "debug.heap.alloc_pattern=1");

    int value = 0;
    ctl_query(ctl_handler, NULL, CTL_QUERY_PROGRAMMATIC,
              "debug.heap.alloc_pattern", CTL_QUERY_READ, &value);
    ASSERT_EQ(value, 1);

    // Test setting alloc_pattern to 2
    ctl_load_config_from_string(ctl_handler, NULL,
                                "debug.heap.alloc_pattern=2");
    ctl_query(ctl_handler, NULL, CTL_QUERY_PROGRAMMATIC,
              "debug.heap.alloc_pattern", CTL_QUERY_READ, &value);
    ASSERT_EQ(value, 2);

    // Test setting alloc_pattern to 0
    ctl_load_config_from_string(ctl_handler, NULL,
                                "debug.heap.alloc_pattern=0");
    ctl_query(ctl_handler, NULL, CTL_QUERY_PROGRAMMATIC,
              "debug.heap.alloc_pattern", CTL_QUERY_READ, &value);
    ASSERT_EQ(value, 0);

    // Negative test: non-existent configuration
    ASSERT_NE(ctl_query(ctl_handler, NULL, CTL_QUERY_PROGRAMMATIC,
                        "debug.heap.non_existent", CTL_QUERY_READ, &value),
              0);

    // Negative test: invalid path
    ASSERT_NE(ctl_query(ctl_handler, NULL, CTL_QUERY_PROGRAMMATIC,
                        "invalid.path.alloc_pattern", CTL_QUERY_READ, &value),
              0);

    debug_ctl_register(ctl_handler);
    deinitialize_debug_ctl();
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
#ifndef _WIN32
    ASSERT_EQ(ctl_config_write_to_file(
                  "config.txt", "debug.heap.alloc_pattern=321;\ndebug.heap."
                                "enable_logging=1;\ndebug.heap.log_level=5;\n"),
              0);
    initialize_debug_ctl();
    auto ctl_handler = get_debug_ctl();
    ASSERT_EQ(ctl_load_config_from_file(ctl_handler, NULL, "config.txt"), 0);

    int value = 0;
    ctl_query(ctl_handler, NULL, CTL_QUERY_PROGRAMMATIC,
              "debug.heap.alloc_pattern", CTL_QUERY_READ, &value);
    ASSERT_EQ(value, 321);

    value = 0;
    ctl_query(ctl_handler, NULL, CTL_QUERY_PROGRAMMATIC, "debug.heap.log_level",
              CTL_QUERY_READ, &value);
    ASSERT_EQ(value, 5);

    value = 0;
    ctl_query(ctl_handler, NULL, CTL_QUERY_PROGRAMMATIC,
              "debug.heap.enable_logging", CTL_QUERY_READ, &value);
    ASSERT_EQ(value, 1);

    debug_ctl_register(ctl_handler);
    deinitialize_debug_ctl();
#endif
}
