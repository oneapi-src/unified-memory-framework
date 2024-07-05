# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

message(STATUS "Checking for module 'libumf' using find_library()")

find_library(LIBUMF_LIBRARY NAMES libumf umf)
set(LIBUMF_LIBRARIES ${LIBUMF_LIBRARY})

get_filename_component(LIBUMF_LIB_DIR ${LIBUMF_LIBRARIES} DIRECTORY)
set(LIBUMF_LIBRARY_DIRS ${LIBUMF_LIB_DIR})

find_file(LIBUMF_HEADER NAMES umf.h)
get_filename_component(LIBUMF_INCLUDE_DIR ${LIBUMF_HEADER} DIRECTORY)
set(LIBUMF_INCLUDE_DIRS ${LIBUMF_INCLUDE_DIR})

if(LIBUMF_LIBRARY)
    message(STATUS "  Found libumf using find_library()")
    message(STATUS "    LIBUMF_LIBRARIES = ${LIBUMF_LIBRARIES}")
    message(STATUS "    LIBUMF_INCLUDE_DIRS = ${LIBUMF_INCLUDE_DIRS}")
    message(STATUS "    LIBUMF_LIBRARY_DIRS = ${LIBUMF_LIBRARY_DIRS}")
else()
    set(MSG_NOT_FOUND
        "libumf NOT found (set CMAKE_PREFIX_PATH to point the location)")
    if(LIBUMF_FIND_REQUIRED)
        message(FATAL_ERROR ${MSG_NOT_FOUND})
    else()
        message(WARNING ${MSG_NOT_FOUND})
    endif()
endif()
