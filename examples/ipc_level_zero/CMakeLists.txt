# Copyright (C) 2024-2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14.0 FATAL_ERROR)
project(umf_example_ipc_level_zero LANGUAGES C)
enable_testing()

set(UMF_EXAMPLE_DIR "${CMAKE_SOURCE_DIR}/..")
list(APPEND CMAKE_MODULE_PATH "${UMF_EXAMPLE_DIR}/cmake")
message(STATUS "CMAKE_MODULE_PATH=${CMAKE_MODULE_PATH}")

find_package(PkgConfig)
pkg_check_modules(LIBUMF libumf)
if(NOT LIBUMF_FOUND)
    find_package(LIBUMF REQUIRED libumf)
endif()

pkg_check_modules(LIBHWLOC hwloc>=2.3.0)
if(NOT LIBHWLOC_FOUND)
    find_package(LIBHWLOC 2.3.0 REQUIRED hwloc)
endif()

pkg_check_modules(ZE_LOADER ze_loader)
if(NOT ZE_LOADER_FOUND)
    find_package(ZE_LOADER REQUIRED ze_loader)
endif()

set(EXAMPLE_NAME umf_example_ipc_level_zero)
set(IPC_LEVEL_ZERO_SM_LIBRARY_DIRS
    ${LIBUMF_LIBRARY_DIRS} ${LIBHWLOC_LIBRARY_DIRS} ${ZE_LOADER_LIBRARY_DIRS})
set(IPC_LEVEL_ZERO_SM_INCLUDE_DIRS
    ${LIBUMF_INCLUDE_DIRS} ${ZE_LOADER_INCLUDE_DIRS} ${UMF_EXAMPLE_DIR}/common)

# build the example
add_executable(
    ${EXAMPLE_NAME} ipc_level_zero.c
                    ${UMF_EXAMPLE_DIR}/common/examples_level_zero_helpers.c)
target_include_directories(${EXAMPLE_NAME}
                           PRIVATE ${IPC_LEVEL_ZERO_SM_INCLUDE_DIRS})
target_link_directories(${EXAMPLE_NAME} PRIVATE
                        ${IPC_LEVEL_ZERO_SM_LIBRARY_DIRS})
target_link_options(${EXAMPLE_NAME} PRIVATE "-Wl,--start-group")
target_link_libraries(${EXAMPLE_NAME} PRIVATE stdc++ ze_loader
                                              ${LIBUMF_LIBRARIES})
target_link_options(${EXAMPLE_NAME} PRIVATE "-Wl,--end-group")

# an optional part - adds a test of this example
add_test(
    NAME ${EXAMPLE_NAME}
    COMMAND ${EXAMPLE_NAME}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

set_tests_properties(${EXAMPLE_NAME} PROPERTIES LABELS "example-standalone")

if(LINUX)
    # set LD_LIBRARY_PATH
    string(JOIN ":" IPC_LEVEL_ZERO_SM_LIBRARY_DIRS_JOINED
           ${IPC_LEVEL_ZERO_SM_LIBRARY_DIRS})
    set_property(
        TEST ${EXAMPLE_NAME}
        PROPERTY
            ENVIRONMENT_MODIFICATION
            "LD_LIBRARY_PATH=path_list_prepend:${IPC_LEVEL_ZERO_SM_LIBRARY_DIRS_JOINED}"
    )
endif()
