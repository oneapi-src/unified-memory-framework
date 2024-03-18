# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

message(STATUS "Checking for module 'libnuma' using find_library()")

find_library(LIBNUMA_LIBRARY NAMES libnuma numa)
set(LIBNUMA_LIBRARIES ${LIBNUMA_LIBRARY})

if(LIBNUMA_LIBRARY)
    message(STATUS "  Found libnuma using find_library()")
else()
    set(MSG_NOT_FOUND
        "libnuma NOT found (set CMAKE_PREFIX_PATH to point the location)")
    if(LIBNUMA_FIND_REQUIRED)
        message(FATAL_ERROR ${MSG_NOT_FOUND})
    else()
        message(WARNING ${MSG_NOT_FOUND})
    endif()
endif()
