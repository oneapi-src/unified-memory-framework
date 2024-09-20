# Copyright (C) 2023-2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

include(${UMF_CMAKE_SOURCE_DIR}/cmake/helpers.cmake)
include(FindThreads)

set(UMF_UTILS_SOURCES_COMMON utils_common.c utils_log.c utils_load_library.c)

set(UMF_UTILS_SOURCES_POSIX utils_posix_common.c utils_posix_concurrency.c
                            utils_posix_math.c)

set(UMF_UTILS_SOURCES_LINUX utils_linux_common.c)

set(UMF_UTILS_SOURCES_MACOSX utils_macosx_common.c)

set(UMF_UTILS_SOURCES_WINDOWS utils_windows_common.c
                              utils_windows_concurrency.c utils_windows_math.c)

if(UMF_USE_VALGRIND)
    if(UMF_USE_ASAN
       OR UMF_USE_TSAN
       OR UMF_USE_UBSAN
       OR UMF_USE_MSAN)
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
    set(UMF_UTILS_SOURCES ${UMF_UTILS_SOURCES_COMMON}
                          ${UMF_UTILS_SOURCES_POSIX})
    set(UMF_UTILS_LIBS dl)

    if(LINUX)
        set(UMF_UTILS_SOURCES ${UMF_UTILS_SOURCES} ${UMF_UTILS_SOURCES_LINUX})
        set(UMF_UTILS_LIBS ${UMF_UTILS_LIBS} rt) # librt for shm_open()
    elseif(MACOSX)
        set(UMF_UTILS_SOURCES ${UMF_UTILS_SOURCES} ${UMF_UTILS_SOURCES_MACOSX})
    endif()
elseif(WINDOWS)
    set(UMF_UTILS_SOURCES ${UMF_UTILS_SOURCES_COMMON}
                          ${UMF_UTILS_SOURCES_WINDOWS})
endif()

add_library(umf_utils INTERFACE)
add_library(${PROJECT_NAME}::utils ALIAS umf_utils)

target_sources(umf_utils INTERFACE ${UMF_UTILS_SOURCES})
target_link_libraries(umf_utils INTERFACE ${CMAKE_THREAD_LIBS_INIT}
                                          ${UMF_UTILS_LIBS})

target_include_directories(
    umf_utils
    INTERFACE ${VALGRIND_INCLUDE_DIRS}
              $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
              $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)

if(UMF_USE_VALGRIND)
    set(UMF_UTILS_INTERFACE_DEFS "UMF_VG_ENABLED=1")
endif()

set(UMF_UTILS_INTERFACE_DEFS ${UMF_UTILS_INTERFACE_DEFS}
                             ${UMF_COMMON_COMPILE_DEFINITIONS})

target_compile_definitions(umf_utils INTERFACE ${UMF_UTILS_INTERFACE_DEFS})
