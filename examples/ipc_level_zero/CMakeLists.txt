# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set(EXAMPLE_NAME umf_example_ipc_level_zero)

add_umf_executable(
    NAME ${EXAMPLE_NAME}
    SRCS ipc_level_zero.c
    LIBS disjoint_pool ze_loader umf)

target_include_directories(
    ${EXAMPLE_NAME}
    PRIVATE ${LEVEL_ZERO_INCLUDE_DIRS} ${UMF_CMAKE_SOURCE_DIR}/src/utils
            ${UMF_CMAKE_SOURCE_DIR}/include
            ${UMF_CMAKE_SOURCE_DIR}/examples/common)

target_link_directories(${EXAMPLE_NAME} PRIVATE ${LIBHWLOC_LIBRARY_DIRS})

add_test(
    NAME ${EXAMPLE_NAME}
    COMMAND ${EXAMPLE_NAME}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

set_tests_properties(${EXAMPLE_NAME} PROPERTIES LABELS "example")

if(WINDOWS)
    # append PATH to DLLs
    set_property(TEST ${EXAMPLE_NAME} PROPERTY ENVIRONMENT_MODIFICATION
                                               "${DLL_PATH_LIST}")
endif()
