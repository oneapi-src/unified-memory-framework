# Copyright (C) 2023-2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

include(${UMF_CMAKE_SOURCE_DIR}/cmake/helpers.cmake)
include(FindThreads)

set(UMF_UTILS_SOURCES_COMMON utils_common.c utils_log.c utils_load_library.c
                             ../ctl/ctl.c)
set(UMF_UTILS_SOURCES_POSIX utils_posix_common.c utils_posix_concurrency.c)
set(UMF_UTILS_SOURCES_LINUX utils_linux_common.c)
set(UMF_UTILS_SOURCES_MACOSX utils_macosx_common.c)
set(UMF_UTILS_SOURCES_WINDOWS utils_windows_common.c
                              utils_windows_concurrency.c)

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

add_umf_library(
    NAME umf_utils
    TYPE STATIC
    SRCS ${UMF_UTILS_SOURCES}
    LIBS ${UMF_UTILS_LIBS} ${CMAKE_THREAD_LIBS_INIT})

if(NOT UMF_BUILD_SHARED_LIBRARY)
    install(TARGETS umf_utils EXPORT ${PROJECT_NAME}-targets)
endif()
