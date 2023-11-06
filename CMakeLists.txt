# Copyright (C) 2022-2023 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14.0 FATAL_ERROR)
project(unified-memory-framework VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED YES)

include(CTest)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(helpers)

# Build Options
option(UMF_DEVELOPER_MODE "enable developer checks, treats warnings as errors" OFF)
option(UMF_BUILD_SHARED_LIBRARY "Build UMF as shared library" OFF)
option(UMF_ENABLE_POOL_TRACKING "Build UMF with pool tracking" ON)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_UMF_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
if(MSVC)
    set(CMAKE_UMF_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/$<CONFIG>)
endif()

# Define a path for custom commands to work around MSVC
set(CUSTOM_COMMAND_BINARY_DIR ${CMAKE_UMF_OUTPUT_DIRECTORY})
if(MSVC)
    # MSVC implicitly adds $<CONFIG> to the output path
    set(CUSTOM_COMMAND_BINARY_DIR ${CUSTOM_COMMAND_BINARY_DIR}/$<CONFIG>)
endif()

# Obtain files for clang-format and license check
set(format_glob)
set(license_glob)
foreach(dir examples include source test tools)
    list(APPEND format_glob
        "${dir}/*.h"
        "${dir}/*.c"
        "${dir}/**/*.h"
        "${dir}/**/*.c")
    list(APPEND license_glob
        "${dir}/*.yml"
        "${dir}/**/*.yml"
        "${dir}/*.py"
        "${dir}/**/*.py"
        "${dir}/**/CMakeLists.txt"
        "${dir}/CMakeLists.txt"
    )
endforeach()
file(GLOB_RECURSE format_src ${format_glob})
file(GLOB_RECURSE license_src ${license_glob})

# A header only library to specify include directories in transitive
# dependencies.
add_library(umf_headers INTERFACE)
# Alias target to support FetchContent.
add_library(${PROJECT_NAME}::headers ALIAS umf_headers)
target_include_directories(umf_headers INTERFACE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

# Add the include directory and the headers target to the install.
install(
    DIRECTORY "${PROJECT_SOURCE_DIR}/include/"
    DESTINATION include COMPONENT umf_headers)
install(
    TARGETS umf_headers
    EXPORT ${PROJECT_NAME}-targets)

add_subdirectory(src)
add_subdirectory(test)

# Add the list of installed targets to the install. This includes the namespace
# which all installed targets will be prefixed with, e.g. for the headers
# target users will depend on ${PROJECT_NAME}::headers.
install(
    EXPORT ${PROJECT_NAME}-targets
    FILE ${PROJECT_NAME}-targets.cmake
    NAMESPACE ${PROJECT_NAME}::
    DESTINATION lib/cmake/${PROJECT_NAME})

# Configure the package versions file for use in find_package when installed.
write_basic_package_version_file(
    ${PROJECT_BINARY_DIR}/cmake/${PROJECT_NAME}-config-version.cmake
    COMPATIBILITY SameMajorVersion)
# Configure the package file that is searched for by find_package when
# installed.
configure_package_config_file(
    ${PROJECT_SOURCE_DIR}/cmake/${PROJECT_NAME}-config.cmake.in
    ${PROJECT_BINARY_DIR}/cmake/${PROJECT_NAME}-config.cmake
    INSTALL_DESTINATION lib/cmake/${PROJECT_NAME})

# Add the package files to the install.
install(
    FILES
        ${PROJECT_BINARY_DIR}/cmake/${PROJECT_NAME}-config.cmake
        ${PROJECT_BINARY_DIR}/cmake/${PROJECT_NAME}-config-version.cmake
    DESTINATION lib/cmake/${PROJECT_NAME})
