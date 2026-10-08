# Copyright (C) 2026 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# Standalone project linking only against an installed UMF via find_package.
cmake_minimum_required(VERSION 3.14.0 FATAL_ERROR)
project(umf_install_consumer LANGUAGES C)
enable_testing()

find_package(umf REQUIRED CONFIG)

add_executable(umf_install_consumer main.c)
target_link_libraries(umf_install_consumer PRIVATE umf::umf umf::umf_headers)

option(UMF_TEST_LINK_USER_HWLOC
       "Also link the system hwloc, as a user application might" OFF)
if(UMF_TEST_LINK_USER_HWLOC)
    # Prefer pkg-config (Linux); fall back to plain find_* (e.g. Windows with
    # CMAKE_PREFIX_PATH pointing at a vcpkg-installed hwloc).
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(USER_HWLOC IMPORTED_TARGET hwloc)
    endif()
    if(USER_HWLOC_FOUND)
        target_link_libraries(umf_install_consumer
                              PRIVATE PkgConfig::USER_HWLOC)
    else()
        find_path(USER_HWLOC_INCLUDE_DIR hwloc.h)
        find_library(USER_HWLOC_LIBRARY hwloc)
        if(NOT USER_HWLOC_INCLUDE_DIR OR NOT USER_HWLOC_LIBRARY)
            message(FATAL_ERROR "User hwloc not found")
        endif()
        target_include_directories(umf_install_consumer
                                   PRIVATE ${USER_HWLOC_INCLUDE_DIR})
        target_link_libraries(umf_install_consumer
                              PRIVATE ${USER_HWLOC_LIBRARY})
    endif()
    target_compile_definitions(umf_install_consumer
                               PRIVATE UMF_TEST_LINK_USER_HWLOC=1)
endif()

add_test(NAME umf_install_consumer COMMAND umf_install_consumer)
