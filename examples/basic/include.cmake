# Copyright (C) 2024-2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# This file is used by two examples: basic and fetch_content.

cmake_minimum_required(VERSION 3.14.0 FATAL_ERROR)
enable_testing()

set(UMF_EXAMPLE_DIR "${CMAKE_SOURCE_DIR}/..")
list(APPEND CMAKE_MODULE_PATH "${UMF_EXAMPLE_DIR}/cmake")
message(STATUS "CMAKE_MODULE_PATH=${CMAKE_MODULE_PATH}")

find_package(PkgConfig)

include("find_umf.cmake")
if(NOT LIBUMF_FOUND)
    message(FATAL_ERROR "libumf NOT found!")
endif()

message(STATUS "Found libumf:")
message(STATUS "    LIBUMF_LIBRARIES = ${LIBUMF_LIBRARIES}")
message(STATUS "    LIBUMF_INCLUDE_DIRS = ${LIBUMF_INCLUDE_DIRS}")
message(STATUS "    LIBUMF_LIBRARY_DIRS = ${LIBUMF_LIBRARY_DIRS}")

pkg_check_modules(LIBHWLOC hwloc>=2.3.0)
if(NOT LIBHWLOC_FOUND)
    find_package(LIBHWLOC 2.3.0 REQUIRED hwloc)
endif()

pkg_check_modules(TBB tbb)
if(NOT TBB_FOUND)
    find_package(TBB REQUIRED tbb)
endif()

# build the example (the basic.c source file is used by two examples: basic and
# fetch_content)
add_executable(${EXAMPLE_NAME} ${CMAKE_SOURCE_DIR}/../basic/basic.c)
target_include_directories(${EXAMPLE_NAME} PRIVATE ${LIBUMF_INCLUDE_DIRS})
target_link_directories(${EXAMPLE_NAME} PRIVATE ${LIBHWLOC_LIBRARY_DIRS})
target_link_libraries(${EXAMPLE_NAME} PRIVATE ${LIBUMF_LIBRARIES} hwloc)

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
endif()

# an optional part - adds a test of this example
add_test(
    NAME ${EXAMPLE_NAME}
    COMMAND ${EXAMPLE_NAME}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

set_tests_properties(${EXAMPLE_NAME} PROPERTIES LABELS "example-standalone")

if(LINUX)
    # set LD_LIBRARY_PATH
    set_property(
        TEST ${EXAMPLE_NAME}
        PROPERTY
            ENVIRONMENT_MODIFICATION
            "LD_LIBRARY_PATH=path_list_append:${LIBUMF_LIBRARY_DIRS};LD_LIBRARY_PATH=path_list_append:${LIBHWLOC_LIBRARY_DIRS}"
    )
endif()
