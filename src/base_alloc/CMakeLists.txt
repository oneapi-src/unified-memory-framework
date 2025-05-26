# Copyright (C) 2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

include(${UMF_CMAKE_SOURCE_DIR}/cmake/helpers.cmake)

set(UMF_BA_SOURCES_COMMON base_alloc_global.c base_alloc.c base_alloc_linear.c)
set(UMF_BA_SOURCES_LINUX base_alloc_linux.c)
set(UMF_BA_SOURCES_WINDOWS base_alloc_windows.c)

if(LINUX OR MACOSX)
    set(UMF_BA_SOURCES ${UMF_BA_SOURCES_COMMON} ${UMF_BA_SOURCES_LINUX})
elseif(WINDOWS)
    set(UMF_BA_SOURCES ${UMF_BA_SOURCES_COMMON} ${UMF_BA_SOURCES_WINDOWS})
endif()

add_umf_library(
    NAME umf_ba
    TYPE STATIC
    SRCS ${UMF_BA_SOURCES}
    LIBS umf_utils)

target_include_directories(umf_ba
                           PRIVATE ${UMF_CMAKE_SOURCE_DIR}/src/base_alloc)

if(NOT UMF_BUILD_SHARED_LIBRARY)
    install(TARGETS umf_ba EXPORT ${PROJECT_NAME}-targets)
endif()
