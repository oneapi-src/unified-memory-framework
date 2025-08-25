# Copyright (C) 2023-2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set(COMMON_SOURCES
    test_helpers.c
    pool_null.c
    pool_trace.c
    provider_null.c
    provider_trace.c)

if(LINUX)
    set(COMMON_SOURCES ${COMMON_SOURCES} test_helpers_linux.c)
endif(LINUX)

add_umf_library(
    NAME umf_test_common
    TYPE STATIC
    SRCS ${COMMON_SOURCES})

target_include_directories(umf_test_common
                           PRIVATE ${UMF_CMAKE_SOURCE_DIR}/include)

if(UMF_BUILD_LEVEL_ZERO_PROVIDER)
    add_library(umf_test_mocks STATIC level_zero_mocks.cpp)
    target_link_libraries(umf_test_mocks GTest::gmock umf_utils)
    target_include_directories(
        umf_test_mocks PUBLIC ${UMF_CMAKE_SOURCE_DIR}/include ${UMF_SRC_DIR}
                              ${UMF_UTILS_DIR} ${LEVEL_ZERO_INCLUDE_DIRS})

    add_umf_library(
        NAME umf_ze_loopback
        TYPE SHARED
        SRCS ze_loopback.cpp
        LINUX_MAP_FILE ${CMAKE_CURRENT_SOURCE_DIR}/ze_loopback.map
        WINDOWS_DEF_FILE ${CMAKE_CURRENT_SOURCE_DIR}/ze_loopback.def)

    target_include_directories(umf_ze_loopback
                               PUBLIC ${LEVEL_ZERO_INCLUDE_DIRS})
endif()
