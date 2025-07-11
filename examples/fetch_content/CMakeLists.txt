# Copyright (C) 2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# This example shows and tests usage of FetchContent module. It downloads and
# builds the UMF library defined in UMF_REPO CMake variable (or UMF from
# upstream repo URL, by default).

cmake_minimum_required(VERSION 3.14.0 FATAL_ERROR)
project(umf_example_fetch_content LANGUAGES C)
enable_testing()

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(LINUX TRUE)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set(WINDOWS TRUE)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set(MACOSX TRUE)
else()
    message(FATAL_ERROR "Unknown OS type")
endif()

set(UMF_EXAMPLE_DIR "${CMAKE_SOURCE_DIR}/..")
list(APPEND CMAKE_MODULE_PATH "${UMF_EXAMPLE_DIR}/cmake")
message(STATUS "CMAKE_MODULE_PATH=${CMAKE_MODULE_PATH}")

include("fetch_umf.cmake")

find_package(PkgConfig)
pkg_check_modules(LIBHWLOC hwloc>=2.3.0)
if(NOT LIBHWLOC_FOUND)
    find_package(LIBHWLOC 2.3.0 REQUIRED hwloc)
endif()

pkg_check_modules(TBB tbb)
if(NOT TBB_FOUND)
    find_package(TBB REQUIRED tbb)
endif()

# build the example
set(EXAMPLE_NAME umf_example_fetch_content)
# reusing the basic.c source file from the basic example
add_executable(${EXAMPLE_NAME} ${CMAKE_SOURCE_DIR}/../basic/basic.c)
target_include_directories(${EXAMPLE_NAME} PRIVATE ${LIBUMF_INCLUDE_DIRS})
target_link_directories(${EXAMPLE_NAME} PRIVATE ${LIBHWLOC_LIBRARY_DIRS})
target_link_libraries(${EXAMPLE_NAME} PRIVATE ${LIBUMF_LIBRARIES} hwloc)

message(STATUS "LIBUMF_INCLUDE_DIRS=${LIBUMF_INCLUDE_DIRS}")
message(STATUS "LIBUMF_LIBRARIES=${LIBUMF_LIBRARIES}")
message(STATUS "LIBUMF_LIBRARY_DIRS=${LIBUMF_LIBRARY_DIRS}")
message(STATUS "LIBHWLOC_LIBRARY_DIRS=${LIBHWLOC_LIBRARY_DIRS}")

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
elseif(WINDOWS)
    # add PATH to DLL on Windows
    set(DLL_PATH_LIST
        "${DLL_PATH_LIST};PATH=path_list_append:${LIBHWLOC_DLL_DIRS};PATH=path_list_append:${TBB_DLL_DIRS}"
    )

    message(STATUS "DLL_PATH_LIST=${DLL_PATH_LIST}")

    # append PATH to DLLs NOTE: this would work only for the CMake ver >= #
    # 3.22. For the older versions, the PATH variable should be set in the test
    # script)
    set_property(TEST ${EXAMPLE_NAME} PROPERTY ENVIRONMENT_MODIFICATION
                                               "${DLL_PATH_LIST}")
endif()
