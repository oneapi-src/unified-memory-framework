# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14.0 FATAL_ERROR)
project(umf_example_dram_and_fsdax LANGUAGES C)
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

pkg_check_modules(JEMALLOC jemalloc)
if(NOT JEMALLOC_FOUND)
    find_package(JEMALLOC REQUIRED jemalloc)
endif()

# build the example
set(EXAMPLE_NAME umf_example_dram_and_fsdax)
add_executable(${EXAMPLE_NAME} dram_and_fsdax.c)
target_include_directories(${EXAMPLE_NAME} PRIVATE ${LIBUMF_INCLUDE_DIRS})

target_link_directories(
    ${EXAMPLE_NAME}
    PRIVATE
    ${LIBUMF_LIBRARY_DIRS}
    ${LIBHWLOC_LIBRARY_DIRS}
    ${JEMALLOC_LIBRARY_DIRS})

target_link_libraries(
    ${EXAMPLE_NAME} PRIVATE hwloc jemalloc_pool ${JEMALLOC_LIBRARIES}
                            ${LIBUMF_LIBRARIES})

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
            "LD_LIBRARY_PATH=path_list_append:${LIBUMF_LIBRARY_DIRS};LD_LIBRARY_PATH=path_list_append:${LIBHWLOC_LIBRARY_DIRS};LD_LIBRARY_PATH=path_list_append:${JEMALLOC_LIBRARY_DIRS}"
    )
endif()
