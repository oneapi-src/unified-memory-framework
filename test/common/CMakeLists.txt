# Copyright (C) 2023 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set(COMMON_SOURCES
    test_helpers.c
    pool_null.c
    pool_trace.c
    provider_null.c
    provider_trace.c
)

add_umf_library(test_common STATIC ${COMMON_SOURCES})

target_include_directories(test_common PRIVATE ../../include)
