# Copyright (C) 2023-2024 Intel Corporation
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
