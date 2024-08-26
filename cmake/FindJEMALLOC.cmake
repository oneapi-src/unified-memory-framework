# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

message(STATUS "Checking for module 'jemalloc' using find_library()")

find_library(JEMALLOC_LIBRARY NAMES libjemalloc jemalloc)
set(JEMALLOC_LIBRARIES ${JEMALLOC_LIBRARY})

get_filename_component(JEMALLOC_LIB_DIR ${JEMALLOC_LIBRARIES} DIRECTORY)
set(JEMALLOC_LIBRARY_DIRS ${JEMALLOC_LIB_DIR})

find_file(JEMALLOC_HEADER NAMES "jemalloc/jemalloc.h")
if(JEMALLOC_HEADER)
    get_filename_component(JEMALLOC_INCLUDE_DIR_TBB ${JEMALLOC_HEADER}
                           DIRECTORY)
    get_filename_component(JEMALLOC_INCLUDE_DIR ${JEMALLOC_INCLUDE_DIR_TBB}
                           DIRECTORY)
    set(JEMALLOC_INCLUDE_DIRS ${JEMALLOC_INCLUDE_DIR})
else()
    set(MSG_NOT_FOUND "<jemalloc/jemalloc.h> header NOT found "
                      "(set CMAKE_PREFIX_PATH to point the location)")
    if(JEMALLOC_FIND_REQUIRED)
        message(FATAL_ERROR ${MSG_NOT_FOUND})
    else()
        message(WARNING ${MSG_NOT_FOUND})
    endif()
endif()

if(WINDOWS)
    find_file(JEMALLOC_DLL NAMES "bin/jemalloc.dll" "jemalloc.dll")
    get_filename_component(JEMALLOC_DLL_DIR ${JEMALLOC_DLL} DIRECTORY)
    set(JEMALLOC_DLL_DIRS ${JEMALLOC_DLL_DIR})
endif()

if(JEMALLOC_LIBRARY)
    message(STATUS "  Found jemalloc using find_library()")
    message(STATUS "    JEMALLOC_LIBRARIES = ${JEMALLOC_LIBRARIES}")
    message(STATUS "    JEMALLOC_INCLUDE_DIRS = ${JEMALLOC_INCLUDE_DIRS}")
    message(STATUS "    JEMALLOC_LIBRARY_DIRS = ${JEMALLOC_LIBRARY_DIRS}")
    if(WINDOWS)
        message(STATUS "    JEMALLOC_DLL_DIRS = ${JEMALLOC_DLL_DIRS}")
    endif()
else()
    set(MSG_NOT_FOUND
        "jemalloc NOT found (set CMAKE_PREFIX_PATH to point the location)")
    if(JEMALLOC_FIND_REQUIRED)
        message(FATAL_ERROR ${MSG_NOT_FOUND})
    else()
        message(WARNING ${MSG_NOT_FOUND})
    endif()
endif()
