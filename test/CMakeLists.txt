# Copyright (C) 2022-2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED YES)

include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        release-1.12.1
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)
enable_testing()

set(UMF_TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR})

function(add_umf_test)
    # NAME - a name of the test
    # SRCS - source files
    # LIBS - libraries to be linked with
    set(oneValueArgs NAME)
    set(multiValueArgs SRCS LIBS)
    cmake_parse_arguments(ARG "" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    set(TEST_NAME umf-${ARG_NAME})
    set(TEST_TARGET_NAME umf_test-${ARG_NAME})

    set(TEST_LIBS test_common
        umf
        GTest::gtest_main
        ${ARG_LIBS})
    add_umf_executable(NAME ${TEST_TARGET_NAME} SRCS ${ARG_SRCS} LIBS ${TEST_LIBS})

    target_include_directories(${TEST_TARGET_NAME} PRIVATE
        ${UMF_CMAKE_SOURCE_DIR}/include
        ${UMF_CMAKE_SOURCE_DIR}/src
        ${UMF_CMAKE_SOURCE_DIR}/src/base_alloc
        ${UMF_TEST_DIR}/common
        ${UMF_TEST_DIR})

    add_test(NAME ${TEST_NAME}
        COMMAND ${TEST_TARGET_NAME}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

    set_tests_properties(${TEST_NAME} PROPERTIES LABELS "umf")

    if(WIN32)
        set_property(TEST ${TEST_NAME} PROPERTY ENVIRONMENT_MODIFICATION 
            "PATH=path_list_append:../bin/$<CONFIG>")
    endif()

    if (UMF_ENABLE_POOL_TRACKING)
        target_compile_definitions(${TEST_TARGET_NAME} PRIVATE UMF_ENABLE_POOL_TRACKING_TESTS=1)
    endif()
endfunction()

add_subdirectory(common)

add_umf_test(NAME base 
             SRCS base.cpp)
add_umf_test(NAME memoryPool
             SRCS memoryPoolAPI.cpp malloc_compliance_tests.cpp)
add_umf_test(NAME memoryProvider
             SRCS memoryProviderAPI.cpp)

if(UMF_BUILD_LIBUMF_POOL_DISJOINT)
    add_umf_test(NAME disjointPool
                 SRCS pools/disjoint_pool.cpp malloc_compliance_tests.cpp
                 LIBS disjoint_pool)
    add_umf_test(NAME c_api_disjoint_pool
                 SRCS c_api/disjoint_pool.c
                 LIBS disjoint_pool)
endif()

if(UMF_BUILD_OS_MEMORY_PROVIDER)
    if(UMF_BUILD_LIBUMF_POOL_JEMALLOC)
        # TODO: we link directly with libc to force using malloc from glibc
        # This is a temporary fix for https://github.com/oneapi-src/unified-memory-framework/issues/161
        add_umf_test(NAME jemalloc_pool
                    SRCS pools/jemalloc_pool.cpp malloc_compliance_tests.cpp
                    LIBS c jemalloc_pool)
    endif()
else()
    message(STATUS "The jemalloc_pool test is DISABLED, because it uses OS_MEMORY_PROVIDER, while the UMF_BUILD_OS_MEMORY_PROVIDER option is set to OFF")
endif()

if(UMF_BUILD_OS_MEMORY_PROVIDER)
    if(UMF_BUILD_LIBUMF_POOL_SCALABLE)
        add_umf_test(NAME scalable_pool
                    SRCS pools/scalable_pool.cpp malloc_compliance_tests.cpp
                    LIBS scalable_pool)
    endif()
else()
    message(STATUS "The scalable_pool test is DISABLED, because it uses OS_MEMORY_PROVIDER, while the UMF_BUILD_OS_MEMORY_PROVIDER option is set to OFF")
endif()

if(UMF_BUILD_OS_MEMORY_PROVIDER AND LINUX) # OS-specific functions are implemented only for Linux now
    add_umf_test(NAME provider_os_memory
                 SRCS provider_os_memory.cpp
                 LIBS umf_utils)
    add_umf_test(NAME memspace_numa
                 SRCS memspace_numa.cpp
                 LIBS numa)
    add_umf_test(NAME provider_os_memory_config
                 SRCS provider_os_memory_config.cpp
                 LIBS umf_utils numa)
endif()

# TODO: add Windows tests
if(LINUX)
    # the base_alloc test uses linux pthreads
    add_umf_test(NAME base_alloc
                SRCS test_base_alloc.c
                LIBS umf_utils)
endif()
