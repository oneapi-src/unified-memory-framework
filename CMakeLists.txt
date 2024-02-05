# Copyright (C) 2022-2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14.0 FATAL_ERROR)
project(unified-memory-framework VERSION 0.1.0 LANGUAGES C)

# Build Options
option(UMF_BUILD_SHARED_LIBRARY "Build UMF as shared library" OFF)
option(UMF_BUILD_OS_MEMORY_PROVIDER "Build OS memory provider" ON)
option(UMF_BUILD_LIBUMF_POOL_DISJOINT "Build the libumf_pool_disjoint static library" OFF)
option(UMF_BUILD_LIBUMF_POOL_JEMALLOC "Build the libumf_pool_jemalloc static library" OFF)
option(UMF_BUILD_LIBUMF_POOL_SCALABLE "Build the libumf_pool_scalable static library" OFF)
option(UMF_BUILD_TESTS "Build UMF tests" ON)
option(UMF_BUILD_BENCHMARKS "Build UMF benchmarks" OFF)
option(UMF_ENABLE_POOL_TRACKING "Build UMF with pool tracking" ON)
option(UMF_DEVELOPER_MODE "Enable developer checks, treats warnings as errors" OFF)
option(UMF_FORMAT_CODE_STYLE "Format UMF code with clang-format" OFF)
option(USE_ASAN "Enable AddressSanitizer checks" OFF)
option(USE_UBSAN "Enable UndefinedBehaviorSanitizer checks" OFF)
option(USE_TSAN "Enable ThreadSanitizer checks" OFF)
option(USE_MSAN "Enable MemorySanitizer checks" OFF)

# For using the options listed in the OPTIONS_REQUIRING_CXX variable
# a C++17 compiler is required. Moreover, if these options are not set,
# CMake will set up a strict C build, without C++ support.
set(OPTIONS_REQUIRING_CXX
    "UMF_BUILD_TESTS"
    "UMF_BUILD_LIBUMF_POOL_DISJOINT")
foreach(option_name ${OPTIONS_REQUIRING_CXX})
    if(${option_name})
        enable_language(CXX)
        set(CMAKE_CXX_STANDARD 17)
        set(CMAKE_CXX_STANDARD_REQUIRED YES)
        break()
    endif()
endforeach()

include(CTest)
include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(helpers)

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(LINUX TRUE)
    set(OS_NAME "linux")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set(WINDOWS TRUE)
    set(OS_NAME "windows")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set(MACOSX TRUE)
    set(OS_NAME "macosx")
else()
    message(FATAL_ERROR "Unknown OS type")
endif()

# needed when UMF is used as an external project
set(UMF_CMAKE_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

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

# Sanitizer flags
if(USE_ASAN)
    add_sanitizer_flag(address)
endif()
if(USE_UBSAN)
    add_sanitizer_flag(undefined)
endif()
if(USE_TSAN)
    add_sanitizer_flag(thread)
endif()
if(USE_MSAN)
    message(WARNING "MemorySanitizer requires instrumented libraries to prevent reporting false-positives")
    add_sanitizer_flag(memory)
endif()

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
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(
    TARGETS umf_headers
    EXPORT ${PROJECT_NAME}-targets)

add_subdirectory(src)

if(UMF_BUILD_TESTS)
    add_subdirectory(test)
endif()

if(UMF_BUILD_BENCHMARKS)
    if(LINUX)
        add_subdirectory(benchmark)
    else()
        message(FATAL_ERROR "benchmarks are supported on Linux only")
    endif()
endif()

# Check if clang-format (in correct version) is available for code formatting.
if(UMF_FORMAT_CODE_STYLE)
    find_program(CLANG_FORMAT NAMES clang-format-15 clang-format-15.0 clang-format)

    if(CLANG_FORMAT)
        get_program_version_major_minor(${CLANG_FORMAT} CLANG_FORMAT_VERSION)
        message(STATUS "Found clang-format: ${CLANG_FORMAT} (version: ${CLANG_FORMAT_VERSION})")

        set(CLANG_FORMAT_REQUIRED "15.0")
        if(NOT (CLANG_FORMAT_VERSION VERSION_EQUAL CLANG_FORMAT_REQUIRED))
            message(FATAL_ERROR "Required clang-format version is ${CLANG_FORMAT_REQUIRED}")
        endif()
    else()
        message(FATAL_ERROR "UMF_FORMAT_CODE_STYLE=ON, but clang-format not found (required version: ${CLANG_FORMAT_REQUIRED})")
    endif()

    # Obtain files for clang-format check
    set(format_glob)
    foreach(DIR IN ITEMS include src test benchmark)
        list(APPEND format_glob
            "${DIR}/*.h"
            "${DIR}/*.hpp"
            "${DIR}/*.c"
            "${DIR}/*.cpp"
            "${DIR}/**/*.h"
            "${DIR}/**/*.hpp"
            "${DIR}/**/*.c"
            "${DIR}/**/*.cpp"
        )
    endforeach()
    file(GLOB_RECURSE format_list ${format_glob})

    message(STATUS "Adding clang-format-check and clang-format-apply make targets")

    add_custom_target(clang-format-check
        COMMAND ${CLANG_FORMAT}
            --style=file
            --dry-run
            -Werror
            ${format_list}
        COMMENT "Check files formatting using clang-format")

    add_custom_target(clang-format-apply
        COMMAND ${CLANG_FORMAT}
            --style=file
            --i
            ${format_list}
        COMMENT "Format files using clang-format")
endif()

# Add license to the installation path
install(FILES ${CMAKE_SOURCE_DIR}/LICENSE.TXT
        DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/doc/${PROJECT_NAME}/")

# Add the list of installed targets to the install. This includes the namespace
# which all installed targets will be prefixed with, e.g. for the headers
# target users will depend on ${PROJECT_NAME}::headers.
install(
    EXPORT ${PROJECT_NAME}-targets
    FILE ${PROJECT_NAME}-targets.cmake
    NAMESPACE ${PROJECT_NAME}::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})

# Configure the package versions file for use in find_package when installed.
write_basic_package_version_file(
    ${PROJECT_BINARY_DIR}/cmake/${PROJECT_NAME}-config-version.cmake
    COMPATIBILITY SameMajorVersion)

# Configure the package file that is searched for by find_package when
# installed.
configure_package_config_file(
    ${PROJECT_SOURCE_DIR}/cmake/${PROJECT_NAME}-config.cmake.in
    ${PROJECT_BINARY_DIR}/cmake/${PROJECT_NAME}-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})

# Add the package files to the install.
install(
    FILES
        ${PROJECT_BINARY_DIR}/cmake/${PROJECT_NAME}-config.cmake
        ${PROJECT_BINARY_DIR}/cmake/${PROJECT_NAME}-config-version.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})

configure_file(
    "${PROJECT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
    "${PROJECT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${PROJECT_BINARY_DIR}/cmake_uninstall.cmake)
