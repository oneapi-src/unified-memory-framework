# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# NOTE: the basic example is always built, even if the TBB required by the
# Scalable Pool is not detected by CMake. If the TBB is not detected during the
# execution of the basic example, the user will receive a corresponding error
# message.
if(NOT UMF_POOL_SCALABLE_ENABLED)
    message(
        WARNING
            "The Basic Example is built but TBB required by Scalable Pool it "
            "uses was not found by CMake. Make sure TBB is added to the default "
            "library search path before running it.")
endif()
set(EXAMPLE_NAME umf_example_basic)

add_umf_executable(
    NAME ${EXAMPLE_NAME}
    SRCS basic.c
    LIBS umf hwloc)

target_include_directories(
    ${EXAMPLE_NAME} PRIVATE ${UMF_CMAKE_SOURCE_DIR}/src/utils
                            ${UMF_CMAKE_SOURCE_DIR}/include)

target_link_directories(${EXAMPLE_NAME} PRIVATE ${LIBHWLOC_LIBRARY_DIRS})

if(UMF_POOL_SCALABLE_ENABLED)
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
endif()
