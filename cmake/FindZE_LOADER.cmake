# Copyright (C) 2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

message(STATUS "Checking for module 'ze_loader' using find_library()")

find_library(ZE_LOADER_LIBRARY NAMES libze_loader ze_loader)
set(ZE_LOADER_LIBRARIES ${ZE_LOADER_LIBRARY})

find_file(ZE_LOADER_HEADER NAMES "ze_api.h" "level_zero/ze_api.h")
get_filename_component(ZE_LOADER_INCLUDE_DIR ${ZE_LOADER_HEADER} DIRECTORY)
set(ZE_LOADER_INCLUDE_DIRS ${ZE_LOADER_INCLUDE_DIR})

get_filename_component(ZE_LOADER_LIB_DIR ${ZE_LOADER_LIBRARIES} DIRECTORY)
set(ZE_LOADER_LIBRARY_DIRS ${ZE_LOADER_LIB_DIR})

if(WINDOWS)
    find_file(ZE_LOADER_DLL NAMES "ze_loader.dll")
    get_filename_component(ZE_LOADER_DLL_DIR ${ZE_LOADER_DLL} DIRECTORY)
    set(ZE_LOADER_DLL_DIRS ${ZE_LOADER_DLL_DIR})
endif()

if(ZE_LOADER_LIBRARY)
    message(STATUS "  Found ZE_LOADER using find_library()")
    message(STATUS "    ZE_LOADER_LIBRARIES = ${ZE_LOADER_LIBRARIES}")
    message(STATUS "    ZE_LOADER_INCLUDE_DIRS = ${ZE_LOADER_INCLUDE_DIRS}")
    message(STATUS "    ZE_LOADER_LIBRARY_DIRS = ${ZE_LOADER_LIBRARY_DIRS}")
    if(WINDOWS)
        message(STATUS "    ZE_LOADER_DLL_DIRS = ${ZE_LOADER_DLL_DIRS}")
    endif()
else()
    set(MSG_NOT_FOUND "ZE_LOADER NOT found (set CMAKE_PREFIX_PATH to point the "
                      "location)")
    if(ZE_LOADER_FIND_REQUIRED)
        message(FATAL_ERROR ${MSG_NOT_FOUND})
    else()
        message(WARNING ${MSG_NOT_FOUND})
    endif()
endif()
