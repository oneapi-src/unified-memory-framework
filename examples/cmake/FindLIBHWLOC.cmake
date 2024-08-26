# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

message(STATUS "Checking for module 'libhwloc' using find_library()")

find_library(LIBHWLOC_LIBRARY NAMES libhwloc hwloc)
set(LIBHWLOC_LIBRARIES ${LIBHWLOC_LIBRARY})

get_filename_component(LIBHWLOC_LIB_DIR ${LIBHWLOC_LIBRARIES} DIRECTORY)
set(LIBHWLOC_LIBRARY_DIRS ${LIBHWLOC_LIB_DIR})

find_file(LIBHWLOC_HEADER NAMES hwloc.h)
get_filename_component(LIBHWLOC_INCLUDE_DIR ${LIBHWLOC_HEADER} DIRECTORY)
set(LIBHWLOC_INCLUDE_DIRS ${LIBHWLOC_INCLUDE_DIR})

set(HWLOC_VERSION_CODE
    "
#include <stdio.h>
#include <stdlib.h>
#include \"hwloc.h\"

void main(int argc, char** argv) {
    unsigned LIBHWLOC_API_PATCH = HWLOC_API_VERSION & 0xFF;
    unsigned LIBHWLOC_API_MINOR = (HWLOC_API_VERSION >> 8) & 0xFF;
    unsigned LIBHWLOC_API_MAJOR = (HWLOC_API_VERSION >> 16) & 0xFF;
    printf(\"%d.%d.%d\", LIBHWLOC_API_MAJOR, LIBHWLOC_API_MINOR, LIBHWLOC_API_PATCH);
}")

set(HWLOC_VERSION_CODE_FILENAME "hwloc_get_version.c")
file(WRITE "${CMAKE_BINARY_DIR}/${HWLOC_VERSION_CODE_FILENAME}"
     "${HWLOC_VERSION_CODE}")

try_run(
    HWLOC_RUN_RESULT HWLOC_COMPILE_RESULT ${CMAKE_BINARY_DIR}
    "${CMAKE_BINARY_DIR}/${HWLOC_VERSION_CODE_FILENAME}"
    CMAKE_FLAGS "-DINCLUDE_DIRECTORIES=${LIBHWLOC_INCLUDE_DIR}"
    RUN_OUTPUT_VARIABLE LIBHWLOC_API_VERSION)

if(WINDOWS)
    find_file(LIBHWLOC_DLL NAMES "bin/hwloc-15.dll" "bin/libhwloc-15.dll"
                                 "hwloc-15.dll" "libhwloc-15.dll")
    get_filename_component(LIBHWLOC_DLL_DIR ${LIBHWLOC_DLL} DIRECTORY)
    set(LIBHWLOC_DLL_DIRS ${LIBHWLOC_DLL_DIR})
endif()

if(LIBHWLOC_LIBRARY)
    message(STATUS "  Found libhwloc using find_library()")
    message(STATUS "    LIBHWLOC_LIBRARIES = ${LIBHWLOC_LIBRARIES}")
    message(STATUS "    LIBHWLOC_INCLUDE_DIRS = ${LIBHWLOC_INCLUDE_DIRS}")
    message(STATUS "    LIBHWLOC_LIBRARY_DIRS = ${LIBHWLOC_LIBRARY_DIRS}")
    message(STATUS "    LIBHWLOC_API_VERSION = ${LIBHWLOC_API_VERSION}")
    if(WINDOWS)
        message(STATUS "    LIBHWLOC_DLL_DIRS = ${LIBHWLOC_DLL_DIRS}")
    endif()

    if(LIBHWLOC_FIND_VERSION)
        if(NOT LIBHWLOC_API_VERSION)
            message(FATAL_ERROR "Failed to retrieve libhwloc version")
        elseif(NOT LIBHWLOC_API_VERSION VERSION_GREATER_EQUAL
               LIBHWLOC_FIND_VERSION)
            message(
                FATAL_ERROR
                    "    Required version: ${LIBHWLOC_FIND_VERSION}, found ${LIBHWLOC_API_VERSION}"
            )
        endif()
    endif()
else()
    set(MSG_NOT_FOUND
        "libhwloc NOT found (set CMAKE_PREFIX_PATH to point the location)")
    if(LIBHWLOC_FIND_REQUIRED)
        message(FATAL_ERROR ${MSG_NOT_FOUND})
    else()
        message(WARNING ${MSG_NOT_FOUND})
    endif()
endif()
