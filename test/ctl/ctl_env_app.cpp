/*
 *
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

#include <umf.h>
#include <umf/experimental/ctl.h>

static int test_env_defaults(int argc, char **argv) {
    char buf[64] = {0};

    if (argc % 2 != 0) {
        std::cerr << "expected even number of arguments" << std::endl;
        std::cerr << "Usage: env_defaults key1 value1 key2 value2 ..."
                  << std::endl;
        return 1;
    }
    for (int i = 0; i < argc; i += 2) {
        const char *key = argv[i];
        const char *value = argv[i + 1];
        if (umfCtlGet(key, buf, sizeof(buf)) != UMF_RESULT_SUCCESS) {
            fprintf(stderr, "Failed to get control for '%s'\n", key);
            return 1;
        }

        if (strcmp(buf, value) != 0) {
            std::cerr << "Expected value for '" << key << "' to be '" << value
                      << "', but got '" << buf << "'" << std::endl;
            return 1;
        }
    }
    return 0;
}

static int test_logger(int argc, char **argv) {
    char buf[256] = {0};
    int level = 0;

    if (argc != 2) {
        std::cerr << "expected two arguments" << std::endl;
        std::cerr << "Usage: logger log_output log_level" << std::endl;
        return 1;
    }
    umfCtlGet("umf.logger.output", buf, sizeof(buf));
    if (strcmp(buf, argv[0]) != 0) {
        std::cerr << "Expected log_output to be '" << argv[0] << "', but got '"
                  << buf << "'" << std::endl;
        return 1;
    }

    umfCtlGet("umf.logger.level", &level, sizeof(level));
    if (level != atoi(argv[1])) {
        std::cerr << "Expected log_level to be '" << argv[1] << "', but got '"
                  << level << "'" << std::endl;
        return 1;
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <test_name> args..."
                  << std::endl;
        return 1;
    }
    const char *test_name = argv[1];
    argc -= 2;
    argv += 2;
    if (strcmp(test_name, "env_defaults") == 0) {
        return test_env_defaults(argc, argv);
    }

    if (strcmp(test_name, "logger") == 0) {
        return test_logger(argc, argv);
    }
    return 1;
}
