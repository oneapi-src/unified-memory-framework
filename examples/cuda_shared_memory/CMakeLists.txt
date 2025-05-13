# Copyright (C) 2024-2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14.0 FATAL_ERROR)
project(umf_example_cuda_shared_memory LANGUAGES C)
enable_testing()

set(UMF_EXAMPLE_DIR "${CMAKE_SOURCE_DIR}/..")
list(APPEND CMAKE_MODULE_PATH "${UMF_EXAMPLE_DIR}/cmake")
message(STATUS "CMAKE_MODULE_PATH=${CMAKE_MODULE_PATH}")

find_package(PkgConfig)
pkg_check_modules(LIBUMF libumf)
if(NOT LIBUMF_FOUND)
    find_package(LIBUMF REQUIRED libumf)
endif()

pkg_check_modules(LIBHWLOC hwloc>=2.3.0)
if(NOT LIBHWLOC_FOUND)
    find_package(LIBHWLOC 2.3.0 REQUIRED hwloc)
endif()

# the CUDA headers are fetched from the NVIDIA repository
include(FetchContent)

set(CUDA_REPO "https://gitlab.com/nvidia/headers/cuda-individual/cudart.git")
set(CUDA_TAG cuda-12.5.1)
message(STATUS "Fetching CUDA ${CUDA_TAG} from ${CUDA_REPO} ...")

# We don't want to build and include CUDA binaries to our install target. For
# CMake >= 3.28 we use EXCLUDE_FROM_ALL flag to do that, but for older versions
# we need to use FetchContent_Populate.
if(CMAKE_VERSION VERSION_LESS 3.28)
    FetchContent_Declare(
        cuda-headers
        GIT_REPOSITORY ${CUDA_REPO}
        GIT_TAG ${CUDA_TAG})
    FetchContent_Populate(cuda-headers)
else()
    FetchContent_Declare(
        cuda-headers
        GIT_REPOSITORY ${CUDA_REPO}
        GIT_TAG ${CUDA_TAG}
        EXCLUDE_FROM_ALL)
    FetchContent_MakeAvailable(cuda-headers)
endif()

set(CUDA_INCLUDE_DIRS
    ${cuda-headers_SOURCE_DIR}
    CACHE PATH "Path to CUDA headers")

find_package(CUDA REQUIRED cuda)

set(CUDA_SM_LIBRARY_DIRS ${LIBUMF_LIBRARY_DIRS} ${LIBHWLOC_LIBRARY_DIRS}
                         ${CUDA_LIBRARY_DIRS})
set(CUDA_SM_INCLUDE_DIRS ${CUDA_INCLUDE_DIRS} ${LIBUMF_INCLUDE_DIRS}
                         ${UMF_EXAMPLE_DIR}/common)
set(CUDA_SM_LIBS stdc++ ${CUDA_LIBRARIES} ${LIBUMF_LIBRARIES})

# build the example
set(EXAMPLE_NAME umf_example_cuda_shared_memory)
add_executable(${EXAMPLE_NAME} cuda_shared_memory.c)
target_include_directories(${EXAMPLE_NAME} PRIVATE ${CUDA_SM_INCLUDE_DIRS})
target_link_directories(${EXAMPLE_NAME} PRIVATE ${CUDA_SM_LIBRARY_DIRS})
target_link_options(${EXAMPLE_NAME} PRIVATE "-Wl,--start-group")
target_link_libraries(${EXAMPLE_NAME} PRIVATE ${CUDA_SM_LIBS})
target_link_options(${EXAMPLE_NAME} PRIVATE "-Wl,--end-group")

# an optional part - adds a test of this example
add_test(
    NAME ${EXAMPLE_NAME}
    COMMAND ${EXAMPLE_NAME}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

set_tests_properties(${EXAMPLE_NAME} PROPERTIES LABELS "example-standalone")

if(LINUX)
    # set LD_LIBRARY_PATH
    string(JOIN ":" CUDA_SM_LIBRARY_DIRS_JOINED ${CUDA_SM_LIBRARY_DIRS})
    set_property(
        TEST ${EXAMPLE_NAME}
        PROPERTY
            ENVIRONMENT_MODIFICATION
            "LD_LIBRARY_PATH=path_list_append:${CUDA_SM_LIBRARY_DIRS_JOINED}")
endif()
