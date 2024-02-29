# Copyright (C) 2023 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

include(${UMF_CMAKE_SOURCE_DIR}/cmake/helpers.cmake)
include(FindThreads)

set(UMF_UTILS_SOURCES_POSIX
    utils_posix_common.c
    utils_posix_concurrency.c
    utils_posix_math.c
)

set(UMF_UTILS_SOURCES_WINDOWS
    utils_windows_common.c
    utils_windows_concurrency.c
    utils_windows_math.c
)

if(USE_VALGRIND)
    if (USE_ASAN OR USE_TSAN OR USE_UBSAN OR USE_MSAN)
        message(FATAL_ERROR "Cannot use valgrind and sanitizers together")
    endif()

    if(PkgConfig_FOUND)
        pkg_check_modules(VALGRIND valgrind)
    endif()
    if(NOT VALGRIND_FOUND)
        find_package(VALGRIND REQUIRED valgrind)
    endif()
endif()

if(LINUX OR MACOSX)
    set(UMF_UTILS_SOURCES ${UMF_UTILS_SOURCES_POSIX})
elseif(WINDOWS)
    set(UMF_UTILS_SOURCES ${UMF_UTILS_SOURCES_WINDOWS})
endif()

add_umf_library(NAME umf_utils
                TYPE STATIC
                SRCS ${UMF_UTILS_SOURCES}
                LIBS ${CMAKE_THREAD_LIBS_INIT})

add_library(${PROJECT_NAME}::utils ALIAS umf_utils)

target_include_directories(umf_utils PUBLIC
    ${VALGRIND_INCLUDE_DIRS}
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

if(USE_VALGRIND)
    target_compile_definitions(umf_utils PUBLIC UMF_VG_ENABLED=1)
endif()

install(TARGETS umf_utils
        EXPORT ${PROJECT_NAME}-targets)
