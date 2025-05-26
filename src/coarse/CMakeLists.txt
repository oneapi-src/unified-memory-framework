# Copyright (C) 2024-2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

include(${UMF_CMAKE_SOURCE_DIR}/cmake/helpers.cmake)

set(UMF_COARSE_SOURCES coarse.c ${UMF_CMAKE_SOURCE_DIR}/src/ravl/ravl.c)
set(UMF_COARSE_LIBS umf_utils umf_ba)

add_umf_library(
    NAME umf_coarse
    TYPE STATIC
    SRCS ${UMF_COARSE_SOURCES}
    LIBS ${UMF_COARSE_LIBS})

target_include_directories(
    umf_coarse
    PRIVATE ${UMF_CMAKE_SOURCE_DIR}/src/coarse
            ${UMF_CMAKE_SOURCE_DIR}/src/base_alloc
            ${UMF_CMAKE_SOURCE_DIR}/src/ravl)

if(NOT UMF_BUILD_SHARED_LIBRARY)
    install(TARGETS umf_coarse EXPORT ${PROJECT_NAME}-targets)
endif()
