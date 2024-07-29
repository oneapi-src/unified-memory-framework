# Copyright (C) 2023 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# In MSVC builds, there is no way to determine the actual build type during the
# CMake configuration step. Therefore, this message is printed in all MSVC
# builds.
if(WINDOWS OR NOT CMAKE_BUILD_TYPE STREQUAL "Release")
    message(
        STATUS
            "The benchmarks SHOULD NOT be run in the Debug build type! The benchmarks will be built, however their output is relevant only in the Release build!"
    )
endif()

if(UMF_BUILD_BENCHMARKS_MT)
    include(FindThreads)
endif()

function(add_umf_benchmark)
    # Parameters:
    #
    # * NAME - a name of the benchmark
    # * SRCS - source files
    # * LIBS - libraries to be linked with
    # * LIBDIRS - directories of libraries to be linked with
    set(oneValueArgs NAME)
    set(multiValueArgs SRCS LIBS LIBDIRS)
    cmake_parse_arguments(
        ARG
        ""
        "${oneValueArgs}"
        "${multiValueArgs}"
        ${ARGN})

    set(BENCH_NAME umf-bench-${ARG_NAME})

    set(BENCH_LIBS ${ARG_LIBS} umf)

    add_umf_executable(
        NAME ${BENCH_NAME}
        SRCS ${ARG_SRCS}
        LIBS ${BENCH_LIBS})

    target_include_directories(
        ${BENCH_NAME}
        PRIVATE ${UMF_CMAKE_SOURCE_DIR}/include
                ${UMF_CMAKE_SOURCE_DIR}/src/utils
                ${UMF_CMAKE_SOURCE_DIR}/test/common
                ${UMF_CMAKE_SOURCE_DIR}/examples/common)

    target_link_directories(${BENCH_NAME} PRIVATE ${ARG_LIBDIRS})

    add_test(
        NAME ${BENCH_NAME}
        COMMAND ${BENCH_NAME}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

    # Benchmark passes if it prints "PASSED" in the output, because ubench of
    # scalable pool fails if the confidence interval exceeds maximum permitted
    # 2.5%.
    set_tests_properties(
        ${BENCH_NAME} PROPERTIES
        LABELS "benchmark"
        PASS_REGULAR_EXPRESSION "PASSED")

    if(WINDOWS)
        # append PATH to DLLs
        set_property(TEST ${BENCH_NAME} PROPERTY ENVIRONMENT_MODIFICATION
                                                 "${DLL_PATH_LIST}")
    endif()

    if(UMF_BUILD_LIBUMF_POOL_DISJOINT)
        target_compile_definitions(${BENCH_NAME}
                                   PRIVATE UMF_BUILD_LIBUMF_POOL_DISJOINT=1)
    endif()
    if(UMF_BUILD_LIBUMF_POOL_JEMALLOC)
        target_compile_definitions(${BENCH_NAME}
                                   PRIVATE UMF_BUILD_LIBUMF_POOL_JEMALLOC=1)
    endif()
    if(UMF_POOL_SCALABLE_ENABLED)
        target_compile_definitions(${BENCH_NAME}
                                   PRIVATE UMF_POOL_SCALABLE_ENABLED=1)
    endif()
    if(UMF_BUILD_LEVEL_ZERO_PROVIDER)
        target_compile_definitions(${BENCH_NAME}
                                   PRIVATE UMF_BUILD_LEVEL_ZERO_PROVIDER=1)
    endif()
    if(UMF_BUILD_CUDA_PROVIDER)
        target_compile_definitions(${BENCH_NAME}
                                   PRIVATE UMF_BUILD_CUDA_PROVIDER=1)
    endif()
    if(UMF_BUILD_GPU_TESTS)
        target_compile_definitions(${BENCH_NAME} PRIVATE UMF_BUILD_GPU_TESTS=1)
    endif()
endfunction()

set(LIB_DIRS ${LIBHWLOC_LIBRARY_DIRS})

# optional libraries
if(UMF_BUILD_LIBUMF_POOL_DISJOINT)
    set(LIBS_OPTIONAL ${LIBS_OPTIONAL} disjoint_pool)
endif()
if(UMF_BUILD_LIBUMF_POOL_JEMALLOC)
    set(LIBS_OPTIONAL ${LIBS_OPTIONAL} jemalloc_pool ${JEMALLOC_LIBRARIES})
    set(LIB_DIRS ${LIB_DIRS} ${JEMALLOC_LIBRARY_DIRS})
endif()
if(LINUX)
    set(LIBS_OPTIONAL ${LIBS_OPTIONAL} m)
endif()
if(UMF_BUILD_GPU_TESTS AND UMF_BUILD_LEVEL_ZERO_PROVIDER)
    set(LIBS_OPTIONAL ${LIBS_OPTIONAL} ze_loader)
    # TODO add CUDA
endif()

# BENCHMARKS

add_umf_benchmark(
    NAME ubench
    SRCS ubench.c
    LIBS ${LIBS_OPTIONAL}
    LIBDIRS ${LIB_DIRS})

if(UMF_BUILD_BENCHMARKS_MT)
    add_umf_benchmark(
        NAME multithreaded
        SRCS multithread.cpp
        LIBS ${LIBS_OPTIONAL} ${CMAKE_THREAD_LIBS_INIT}
        LIBDIRS ${LIB_DIRS})
endif()
