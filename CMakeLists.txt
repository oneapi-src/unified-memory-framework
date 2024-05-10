# Copyright (C) 2022-2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14.0 FATAL_ERROR)
project(
    umf
    VERSION 0.1.0
    LANGUAGES C)

# needed when UMF is used as an external project
set(UMF_CMAKE_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

list(APPEND CMAKE_MODULE_PATH "${UMF_CMAKE_SOURCE_DIR}/cmake")
include(${UMF_CMAKE_SOURCE_DIR}/cmake/helpers.cmake)

# CMAKE_PROJECT_VERSION[_MAJOR|_MINOR|_PATCH] variables are set via 'project'
# command. They cannot contain any "pre-release" part, though. We use custom
# "UMF_SRC_VERSION" to store more accurate (source) version - this var should be
# used, e.g., for creating packages.
set_source_version()
message(
    STATUS
        "UMF version: ${CMAKE_PROJECT_VERSION} (source version: ${UMF_SRC_VERSION})"
)

# Build Options
option(UMF_BUILD_SHARED_LIBRARY "Build UMF as shared library" OFF)
option(UMF_BUILD_LEVEL_ZERO_PROVIDER "Build Level Zero memory provider" ON)
option(UMF_BUILD_LIBUMF_POOL_DISJOINT
       "Build the libumf_pool_disjoint static library" OFF)
option(UMF_BUILD_LIBUMF_POOL_JEMALLOC
       "Build the libumf_pool_jemalloc static library" OFF)
option(UMF_BUILD_LIBUMF_POOL_SCALABLE
       "Build the libumf_pool_scalable static library" OFF)
option(UMF_BUILD_TESTS "Build UMF tests" ON)
option(UMF_BUILD_GPU_TESTS "Build UMF GPU tests" OFF)
option(UMF_BUILD_BENCHMARKS "Build UMF benchmarks" OFF)
option(UMF_BUILD_BENCHMARKS_MT "Build UMF multithreaded benchmarks" OFF)
option(UMF_BUILD_EXAMPLES "Build UMF examples" ON)
option(UMF_BUILD_GPU_EXAMPLES "Build UMF GPU examples" OFF)
option(UMF_ENABLE_POOL_TRACKING "Build UMF with pool tracking" ON)
option(UMF_DEVELOPER_MODE "Enable developer checks, treats warnings as errors"
       OFF)
option(UMF_FORMAT_CODE_STYLE
       "Add clang, cmake, and black -format-check and -format-apply targets"
       OFF)
option(USE_ASAN "Enable AddressSanitizer checks" OFF)
option(USE_UBSAN "Enable UndefinedBehaviorSanitizer checks" OFF)
option(USE_TSAN "Enable ThreadSanitizer checks" OFF)
option(USE_MSAN "Enable MemorySanitizer checks" OFF)
option(USE_VALGRIND "Enable Valgrind instrumentation" OFF)

# set UMF_PROXY_LIB_BASED_ON_POOL to one of: SCALABLE or JEMALLOC
set(KNOWN_PROXY_LIB_POOLS SCALABLE JEMALLOC)
set(UMF_PROXY_LIB_BASED_ON_POOL
    SCALABLE
    CACHE STRING
          "A UMF pool the proxy library is based on (SCALABLE or JEMALLOC)")
set_property(CACHE UMF_PROXY_LIB_BASED_ON_POOL
             PROPERTY STRINGS ${KNOWN_PROXY_LIB_POOLS})

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

# This build type check is not possible on Windows when CMAKE_BUILD_TYPE is not
# set, because in this case the build type is determined after a CMake
# configuration is done (at the build time)
if(NOT WINDOWS)
    set(KNOWN_BUILD_TYPES Release Debug RelWithDebInfo MinSizeRel)
    string(REPLACE ";" " " KNOWN_BUILD_TYPES_STR "${KNOWN_BUILD_TYPES}")

    if(NOT CMAKE_BUILD_TYPE)
        message(
            STATUS
                "No build type selected (CMAKE_BUILD_TYPE), defaulting to Release"
        )
        set(CMAKE_BUILD_TYPE "Release")
    else()
        message(STATUS "CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
        if(NOT CMAKE_BUILD_TYPE IN_LIST KNOWN_BUILD_TYPES)
            message(
                WARNING
                    "Unusual build type was set (${CMAKE_BUILD_TYPE}), please make sure it is a correct one. "
                    "The following ones are supported by default: ${KNOWN_BUILD_TYPES_STR}."
            )
        endif()
    endif()

    set(CMAKE_BUILD_TYPE
        "${CMAKE_BUILD_TYPE}"
        CACHE
            STRING
            "Choose the type of build, options are: ${KNOWN_BUILD_TYPES_STR} ..."
            FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS ${KNOWN_BUILD_TYPES})
endif()

# For using the options listed in the OPTIONS_REQUIRING_CXX variable a C++17
# compiler is required. Moreover, if these options are not set, CMake will set
# up a strict C build, without C++ support.
set(OPTIONS_REQUIRING_CXX "UMF_BUILD_TESTS" "UMF_BUILD_LIBUMF_POOL_DISJOINT"
                          "UMF_BUILD_BENCHMARKS_MT")
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
find_package(PkgConfig)

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
    message(WARNING "MemorySanitizer requires instrumented libraries to "
                    "prevent reporting false-positives")
    add_sanitizer_flag(memory)
endif()

# A header only library to specify include directories in transitive
# dependencies.
add_library(umf_headers INTERFACE)

# Alias target to support FetchContent.
add_library(${PROJECT_NAME}::headers ALIAS umf_headers)
target_include_directories(
    umf_headers INTERFACE $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
                          $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

if(WINDOWS)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    # set PATH to DLLs on Windows
    set(DLL_PATH_LIST
        "PATH=path_list_append:${PROJECT_BINARY_DIR}/bin/$<CONFIG>")
    # add path to the proxy lib DLL
    set(DLL_PATH_LIST
        "${DLL_PATH_LIST};PATH=path_list_append:${PROJECT_BINARY_DIR}/src/proxy_lib"
    )
    # MSVC implicitly adds $<CONFIG> to the output path
    set(DLL_PATH_LIST
        "${DLL_PATH_LIST};PATH=path_list_append:${PROJECT_BINARY_DIR}/src/proxy_lib/$<CONFIG>"
    )
endif()

pkg_check_modules(LIBHWLOC hwloc>=2.3.0)
if(NOT LIBHWLOC_FOUND)
    find_package(LIBHWLOC 2.3.0 REQUIRED hwloc)
endif()
# add PATH to DLL on Windows
set(DLL_PATH_LIST
    "${DLL_PATH_LIST};PATH=path_list_append:${LIBHWLOC_LIBRARY_DIRS}/../bin")

if(UMF_BUILD_LIBUMF_POOL_SCALABLE)
    pkg_check_modules(TBB tbb)
    if(NOT TBB_FOUND)
        find_package(TBB REQUIRED tbb)
    endif()
    # add PATH to DLL on Windows
    set(DLL_PATH_LIST
        "${DLL_PATH_LIST};PATH=path_list_append:${TBB_LIBRARY_DIRS}/../bin")
endif()

if(UMF_BUILD_LIBUMF_POOL_JEMALLOC)
    pkg_check_modules(JEMALLOC jemalloc)
    if(NOT JEMALLOC_FOUND)
        find_package(JEMALLOC REQUIRED jemalloc)
    endif()
    # add PATH to DLL on Windows
    set(DLL_PATH_LIST
        "${DLL_PATH_LIST};PATH=path_list_append:${JEMALLOC_LIBRARY_DIRS}/../bin"
    )
endif()

# set UMF_PROXY_LIB_ENABLED
if(WINDOWS)
    # TODO: enable the proxy library in the Debug build on Windows
    #
    # In MSVC builds, there is no way to determine the actual build type during
    # the CMake configuration step. Therefore, this message is printed in all
    # MSVC builds.
    message(
        STATUS
            "The proxy library will be built, however it is supported only in the Release build on Windows"
    )
endif()
if(UMF_PROXY_LIB_BASED_ON_POOL STREQUAL SCALABLE)
    if(UMF_BUILD_LIBUMF_POOL_SCALABLE)
        set(UMF_PROXY_LIB_ENABLED ON)
        set(PROXY_LIB_USES_SCALABLE_POOL ON)
        set(PROXY_LIBS umf scalable_pool)
    else()
        message(
            STATUS
                "Disabling the proxy library, because UMF_PROXY_LIB_BASED_ON_POOL==SCALABLE but UMF_BUILD_LIBUMF_POOL_SCALABLE is OFF"
        )
    endif()
elseif(UMF_PROXY_LIB_BASED_ON_POOL STREQUAL JEMALLOC)
    if(UMF_BUILD_LIBUMF_POOL_JEMALLOC)
        set(UMF_PROXY_LIB_ENABLED ON)
        set(PROXY_LIB_USES_JEMALLOC_POOL ON)
        set(PROXY_LIBS umf jemalloc_pool)
    else()
        message(
            STATUS
                "Disabling the proxy library, because UMF_PROXY_LIB_BASED_ON_POOL==JEMALLOC but UMF_BUILD_LIBUMF_POOL_JEMALLOC is OFF"
        )
    endif()
else()
    message(
        FATAL_ERROR
            "Proxy library: pool manager not chosen or set to a non-supported one (see UMF_PROXY_LIB_BASED_ON_POOL)"
    )
endif()

add_subdirectory(src)

if(UMF_BUILD_TESTS)
    add_subdirectory(test)
endif()

if(UMF_BUILD_BENCHMARKS)
    add_subdirectory(benchmark)
endif()

if(UMF_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(UMF_FORMAT_CODE_STYLE)
    find_program(CLANG_FORMAT NAMES clang-format-15 clang-format-15.0
                                    clang-format)
    find_program(CMAKE_FORMAT NAMES cmake-format)
    find_program(BLACK NAMES black)

    set(CLANG_FORMAT_REQUIRED "15.0")
    set(CMAKE_FORMAT_REQUIRED "0.6")

    if(NOT CLANG_FORMAT
       AND NOT CMAKE_FORMAT
       AND NOT BLACK)
        message(
            FATAL_ERROR
                "UMF_FORMAT_CODE_STYLE=ON, but neither clang-format (required version: "
                "${CLANG_FORMAT_REQUIRED}), nor cmake-format (required version: "
                "${CMAKE_FORMAT_REQUIRED}), nor black was found.")
    endif()

    if(CLANG_FORMAT)
        get_program_version_major_minor(${CLANG_FORMAT} CLANG_FORMAT_VERSION)
        message(STATUS "Found clang-format: ${CLANG_FORMAT} "
                       "(version: ${CLANG_FORMAT_VERSION})")

        # Check if clang-format (in correct version) is available for code
        # formatting.
        if(NOT (CLANG_FORMAT_VERSION VERSION_EQUAL CLANG_FORMAT_REQUIRED))
            message(FATAL_ERROR "Required clang-format version is "
                                "${CLANG_FORMAT_REQUIRED}")
        endif()

        # Obtain files for clang-format check
        set(format_clang_glob)
        foreach(
            DIR IN
            ITEMS benchmark
                  examples
                  include
                  src
                  test)
            list(
                APPEND
                format_clang_glob
                "${DIR}/*.h"
                "${DIR}/*.hpp"
                "${DIR}/*.c"
                "${DIR}/*.cpp"
                "${DIR}/**/*.h"
                "${DIR}/**/*.hpp"
                "${DIR}/**/*.c"
                "${DIR}/**/*.cpp")
        endforeach()
        file(GLOB_RECURSE format_list ${format_clang_glob})

        message(
            STATUS
                "Adding 'clang-format-check' and 'clang-format-apply' targets")

        add_custom_target(
            clang-format-check
            COMMAND ${CLANG_FORMAT} --style=file --dry-run -Werror
                    ${format_list}
            COMMENT "Check files formatting using clang-format")

        add_custom_target(
            clang-format-apply
            COMMAND ${CLANG_FORMAT} --style=file -i ${format_list}
            COMMENT "Format files using clang-format")
    endif()

    if(CMAKE_FORMAT)
        get_program_version_major_minor(${CMAKE_FORMAT} CMAKE_FORMAT_VERSION)
        message(STATUS "Found cmake-format: ${CMAKE_FORMAT} "
                       "(version: ${CMAKE_FORMAT_VERSION})")

        # Check if cmake-format (in correct version) is available for cmake
        # files formatting.
        if(NOT (CMAKE_FORMAT_VERSION VERSION_EQUAL CMAKE_FORMAT_REQUIRED))
            message(FATAL_ERROR "Required cmake-format version is"
                                "${CMAKE_FORMAT_REQUIRED}")
        endif()

        # Obtain files for cmake-format check
        set(format_cmake_glob)
        foreach(
            DIR IN
            ITEMS cmake
                  benchmark
                  examples
                  include
                  src
                  test)
            list(
                APPEND
                format_cmake_glob
                "${DIR}/CMakeLists.txt"
                "${DIR}/*.cmake"
                "${DIR}/**/CMakeLists.txt"
                "${DIR}/**/*.cmake")
        endforeach()
        file(GLOB_RECURSE format_cmake_list ${format_cmake_glob})
        list(APPEND format_cmake_list "${PROJECT_SOURCE_DIR}/CMakeLists.txt")

        message(
            STATUS
                "Adding 'cmake-format-check' and 'cmake-format-apply' targets")

        add_custom_target(
            cmake-format-check
            COMMAND ${CMAKE_FORMAT} --check ${format_cmake_list}
            COMMENT "Check CMake files formatting using cmake-format")

        add_custom_target(
            cmake-format-apply
            COMMAND ${CMAKE_FORMAT} --in-place ${format_cmake_list}
            COMMENT "Format Cmake files using cmake-format")
    endif()

    if(BLACK)
        # black should maintain backward compatibility, we don't have to require
        # a specific version
        get_program_version_major_minor(${BLACK} BLACK_VERSION)
        message(STATUS "Found black: ${BLACK} (version: ${BLACK_VERSION})")

        message(
            STATUS
                "Adding 'black-format-check' and 'black-format-apply' targets")

        add_custom_target(
            black-format-check
            COMMAND ${BLACK} --check --verbose ${CMAKE_SOURCE_DIR}
            COMMENT "Check Python files formatting using black formatter")

        add_custom_target(
            black-format-apply
            COMMAND ${BLACK} ${CMAKE_SOURCE_DIR}
            COMMENT "Format Python files using black formatter")
    endif()

    # Add a convenience target for running all tools at once - available only if
    # all are found.
    if(CLANG_FORMAT
       AND CMAKE_FORMAT
       AND BLACK)
        add_custom_target(
            format-check
            COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target
                    clang-format-check
            COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target
                    cmake-format-check
            COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target
                    black-format-check
            COMMENT "Running all formatting checks")

        add_custom_target(
            format-apply
            COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target
                    clang-format-apply
            COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target
                    cmake-format-apply
            COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target
                    black-format-apply
            COMMENT "Format C/C++, CMake, and Python files")
        message(
            STATUS
                "  Adding convenience targets 'format-check' and 'format-apply'."
        )
    else()
        message(
            STATUS
                "  Convenience targets 'format-check' and 'format-apply' are "
                "not available. Use commands specific for found tools (see the log above)."
        )
    endif()
endif()

# --------------------------------------------------------------------------- #
# Configure make install/uninstall and packages
# --------------------------------------------------------------------------- #
install(FILES ${CMAKE_SOURCE_DIR}/LICENSE.TXT
        DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/doc/${PROJECT_NAME}/")

install(
    FILES examples/basic/gpu_shared_memory.c
          examples/basic/utils_level_zero.h
          examples/basic/basic.c
          examples/basic/ipc_level_zero.c
          examples/basic/ipc_shm_ipcapi.sh
          examples/basic/ipc_shm_ipcapi_consumer.c
          examples/basic/ipc_shm_ipcapi_producer.c
    DESTINATION "${CMAKE_INSTALL_DOCDIR}/examples")

# Add the include directory and the headers target to the install.
install(DIRECTORY "${PROJECT_SOURCE_DIR}/include/"
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(TARGETS umf_headers EXPORT ${PROJECT_NAME}-targets)

# Add the list of installed targets to the install. This includes the namespace
# which all installed targets will be prefixed with, e.g. for the headers target
# users will depend on ${PROJECT_NAME}::headers.
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
install(FILES ${PROJECT_BINARY_DIR}/cmake/${PROJECT_NAME}-config.cmake
              ${PROJECT_BINARY_DIR}/cmake/${PROJECT_NAME}-config-version.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})

# Configure uninstall commands
configure_file("${PROJECT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
               "${PROJECT_BINARY_DIR}/cmake_uninstall.cmake" IMMEDIATE @ONLY)

add_custom_target(uninstall COMMAND ${CMAKE_COMMAND} -P
                                    ${PROJECT_BINARY_DIR}/cmake_uninstall.cmake)
