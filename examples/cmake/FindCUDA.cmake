# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

message(STATUS "Checking for module 'cuda' using find_library()")

find_library(CUDA_LIBRARY NAMES libcuda cuda)
set(CUDA_LIBRARIES ${CUDA_LIBRARY})

get_filename_component(CUDA_LIB_DIR ${CUDA_LIBRARIES} DIRECTORY)
set(CUDA_LIBRARY_DIRS ${CUDA_LIB_DIR})

if(WINDOWS)
    find_file(CUDA_DLL NAMES "bin/cuda.dll" "cuda.dll")
    get_filename_component(CUDA_DLL_DIR ${CUDA_DLL} DIRECTORY)
    set(CUDA_DLL_DIRS ${CUDA_DLL_DIR})
endif()

if(CUDA_LIBRARY)
    message(STATUS "  Found cuda using find_library()")
    message(STATUS "    CUDA_LIBRARIES = ${CUDA_LIBRARIES}")
    message(STATUS "    CUDA_INCLUDE_DIRS = ${CUDA_INCLUDE_DIRS}")
    message(STATUS "    CUDA_LIBRARY_DIRS = ${CUDA_LIBRARY_DIRS}")
    if(WINDOWS)
        message(STATUS "    CUDA_DLL_DIRS = ${CUDA_DLL_DIRS}")
    endif()
else()
    set(MSG_NOT_FOUND "cuda NOT found (set CMAKE_PREFIX_PATH to point the "
                      "location)")
    if(CUDA_FIND_REQUIRED)
        message(FATAL_ERROR ${MSG_NOT_FOUND})
    else()
        message(WARNING ${MSG_NOT_FOUND})
    endif()
endif()
