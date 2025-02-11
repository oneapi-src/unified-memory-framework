# Copyright (C) 2024-2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

include(${UMF_CMAKE_SOURCE_DIR}/cmake/helpers.cmake)

set(COARSE_SOURCES coarse.c ../ravl/ravl.c)

if(UMF_BUILD_SHARED_LIBRARY AND (NOT WINDOWS))
    set(COARSE_EXTRA_SRCS ${BA_SOURCES})
    set(COARSE_EXTRA_LIBS $<BUILD_INTERFACE:umf_utils>)
endif()

add_umf_library(
    NAME coarse
    TYPE STATIC
    SRCS ${COARSE_SOURCES} ${COARSE_EXTRA_SRCS}
    LIBS ${COARSE_EXTRA_LIBS})

target_include_directories(
    coarse
    PRIVATE $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
            $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
            $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/ravl>)

add_library(${PROJECT_NAME}::coarse ALIAS coarse)
