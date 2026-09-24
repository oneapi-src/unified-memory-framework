# Copyright (C) 2026 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# Standalone project linking only against an installed UMF via find_package.
cmake_minimum_required(VERSION 3.14.0 FATAL_ERROR)
project(umf_install_consumer LANGUAGES C)
enable_testing()

find_package(umf REQUIRED CONFIG)

add_executable(umf_install_consumer main.c)
target_link_libraries(umf_install_consumer PRIVATE umf::umf umf::headers)

add_test(NAME umf_install_consumer COMMAND umf_install_consumer)
