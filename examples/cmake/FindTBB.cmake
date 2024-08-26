# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

message(STATUS "Checking for module 'tbb' using find_library()")

find_library(TBB_LIBRARY NAMES libtbbmalloc tbbmalloc)
set(TBB_LIBRARIES ${TBB_LIBRARY})

get_filename_component(TBB_LIB_DIR ${TBB_LIBRARIES} DIRECTORY)
set(TBB_LIBRARY_DIRS ${TBB_LIB_DIR})

find_file(TBB_HEADER NAMES "tbb/scalable_allocator.h")
if(TBB_HEADER)
    get_filename_component(TBB_INCLUDE_DIR_TBB ${TBB_HEADER} DIRECTORY)
    get_filename_component(TBB_INCLUDE_DIR ${TBB_INCLUDE_DIR_TBB} DIRECTORY)
    set(TBB_INCLUDE_DIRS ${TBB_INCLUDE_DIR})
else()
    set(MSG_NOT_FOUND "<tbb/scalable_allocator.h> header NOT found (set "
                      "CMAKE_PREFIX_PATH to point the location)")
    if(TBB_FIND_REQUIRED)
        message(FATAL_ERROR ${MSG_NOT_FOUND})
    else()
        message(WARNING ${MSG_NOT_FOUND})
    endif()
endif()

if(WINDOWS)
    find_file(TBB_DLL NAMES "bin/tbbmalloc.dll" "tbbmalloc.dll")
    get_filename_component(TBB_DLL_DIR ${TBB_DLL} DIRECTORY)
    set(TBB_DLL_DIRS ${TBB_DLL_DIR})
endif()

if(TBB_LIBRARY)
    message(STATUS "  Found tbb using find_library()")
    message(STATUS "    TBB_LIBRARIES = ${TBB_LIBRARIES}")
    message(STATUS "    TBB_INCLUDE_DIRS = ${TBB_INCLUDE_DIRS}")
    message(STATUS "    TBB_LIBRARY_DIRS = ${TBB_LIBRARY_DIRS}")
    if(WINDOWS)
        message(STATUS "    TBB_DLL_DIRS = ${TBB_DLL_DIRS}")
    endif()
else()
    set(MSG_NOT_FOUND "tbb NOT found (set CMAKE_PREFIX_PATH to point the "
                      "location)")
    if(TBB_FIND_REQUIRED)
        message(FATAL_ERROR ${MSG_NOT_FOUND})
    else()
        message(WARNING ${MSG_NOT_FOUND})
    endif()
endif()
