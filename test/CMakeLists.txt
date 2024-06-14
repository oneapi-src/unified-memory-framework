# Copyright (C) 2022-2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED YES)

include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG release-1.12.1)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt
    ON
    CACHE BOOL "" FORCE)
set(INSTALL_GTEST
    OFF
    CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)
enable_testing()

set(UMF_TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR})

function(add_umf_test)
    # Parameters:
    #
    # * NAME - a name of the test
    # * SRCS - source files
    # * LIBS - libraries to be linked with
    set(oneValueArgs NAME)
    set(multiValueArgs SRCS LIBS)
    cmake_parse_arguments(
        ARG
        ""
        "${oneValueArgs}"
        "${multiValueArgs}"
        ${ARGN})

    set(TEST_NAME umf-${ARG_NAME})
    set(TEST_TARGET_NAME umf_test-${ARG_NAME})

    set(LIB_DIRS ${LIB_DIRS} ${LIBHWLOC_LIBRARY_DIRS})

    if(UMF_BUILD_LIBUMF_POOL_JEMALLOC)
        set(LIB_DIRS ${LIB_DIRS} ${JEMALLOC_LIBRARY_DIRS})
    endif()

    set(TEST_LIBS
        test_common
        ${ARG_LIBS}
        GTest::gtest_main
        ${LIBS_OPTIONAL}
        umf)

    add_umf_executable(
        NAME ${TEST_TARGET_NAME}
        SRCS ${ARG_SRCS}
        LIBS ${TEST_LIBS})

    target_link_directories(${TEST_TARGET_NAME} PRIVATE ${LIB_DIRS})

    target_include_directories(
        ${TEST_TARGET_NAME}
        PRIVATE ${UMF_CMAKE_SOURCE_DIR}/include
                ${UMF_CMAKE_SOURCE_DIR}/src
                ${UMF_CMAKE_SOURCE_DIR}/src/base_alloc
                ${UMF_CMAKE_SOURCE_DIR}/src/utils
                ${UMF_TEST_DIR}/common
                ${UMF_TEST_DIR})

    add_test(
        NAME ${TEST_NAME}
        COMMAND ${TEST_TARGET_NAME}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

    set_tests_properties(${TEST_NAME} PROPERTIES LABELS "umf")

    if(WINDOWS)
        # append PATH to DLLs
        set_property(TEST ${TEST_NAME} PROPERTY ENVIRONMENT_MODIFICATION
                                                "${DLL_PATH_LIST}")
    endif()
endfunction()

add_subdirectory(common)

add_umf_test(NAME base SRCS base.cpp)
add_umf_test(NAME memoryPool SRCS memoryPoolAPI.cpp malloc_compliance_tests.cpp)
add_umf_test(NAME memoryProvider SRCS memoryProviderAPI.cpp)

if(UMF_BUILD_SHARED_LIBRARY)
    # if build as shared library, utils symbols won't be visible in tests
    set(UMF_UTILS_FOR_TEST umf_utils)
    if(LINUX OR MACOSX)
        set(UMF_UTILS_SOURCES
            ../src/utils/utils_common.c ../src/utils/utils_posix_common.c
            ../src/utils/utils_posix_concurrency.c)
    elseif(WINDOWS)
        set(UMF_UTILS_SOURCES
            ../src/utils/utils_common.c ../src/utils/utils_windows_common.c
            ../src/utils/utils_windows_concurrency.c)
    endif()
endif()

add_umf_test(NAME logger SRCS utils/utils_log.cpp ${UMF_UTILS_SOURCES})

add_umf_test(
    NAME utils_common
    SRCS utils/utils.cpp
    LIBS ${UMF_UTILS_FOR_TEST})

if(UMF_BUILD_LIBUMF_POOL_DISJOINT)
    add_umf_test(
        NAME disjointPool
        SRCS pools/disjoint_pool.cpp malloc_compliance_tests.cpp
        LIBS disjoint_pool)
    add_umf_test(
        NAME c_api_disjoint_pool
        SRCS c_api/disjoint_pool.c
        LIBS disjoint_pool)
endif()

if(UMF_BUILD_LIBUMF_POOL_DISJOINT
   AND UMF_BUILD_LIBUMF_POOL_JEMALLOC
   AND UMF_POOL_SCALABLE_ENABLED)
    add_umf_test(
        NAME c_api_multi_pool
        SRCS c_api/multi_pool.c
        LIBS disjoint_pool jemalloc_pool ${JEMALLOC_LIBRARIES})
endif()

if(UMF_BUILD_LIBUMF_POOL_JEMALLOC)
    add_umf_test(
        NAME jemalloc_pool
        SRCS pools/jemalloc_pool.cpp malloc_compliance_tests.cpp
        LIBS jemalloc_pool)
endif()

if(UMF_POOL_SCALABLE_ENABLED)
    add_umf_test(NAME scalable_pool SRCS pools/scalable_pool.cpp
                                         malloc_compliance_tests.cpp)
endif()

if(LINUX) # OS-specific functions are implemented only for Linux now
    if(PkgConfig_FOUND)
        pkg_check_modules(LIBNUMA numa)
    endif()
    if(NOT LIBNUMA_FOUND)
        find_package(LIBNUMA REQUIRED numa)
    endif()

    add_umf_test(
        NAME provider_os_memory
        SRCS provider_os_memory.cpp
        LIBS ${UMF_UTILS_FOR_TEST})
    add_umf_test(
        NAME provider_os_memory_multiple_numa_nodes
        SRCS provider_os_memory_multiple_numa_nodes.cpp
        LIBS ${UMF_UTILS_FOR_TEST} ${LIBNUMA_LIBRARIES})
    add_umf_test(
        NAME memspace_numa
        SRCS memspaces/memspace_numa.cpp
        LIBS ${LIBNUMA_LIBRARIES} ${LIBHWLOC_LIBRARIES})
    add_umf_test(
        NAME provider_os_memory_config
        SRCS provider_os_memory_config.cpp
        LIBS ${UMF_UTILS_FOR_TEST} ${LIBNUMA_LIBRARIES} ${LIBHWLOC_LIBRARIES})
    add_umf_test(
        NAME memspace_host_all
        SRCS memspaces/memspace_host_all.cpp
        LIBS ${UMF_UTILS_FOR_TEST} ${LIBNUMA_LIBRARIES} ${LIBHWLOC_LIBRARIES})
    add_umf_test(
        NAME memspace_highest_capacity
        SRCS memspaces/memspace_highest_capacity.cpp
        LIBS ${UMF_UTILS_FOR_TEST} ${LIBNUMA_LIBRARIES} ${LIBHWLOC_LIBRARIES})
    add_umf_test(
        NAME memspace_highest_bandwidth
        SRCS memspaces/memspace_highest_bandwidth.cpp
        LIBS ${UMF_UTILS_FOR_TEST} ${LIBNUMA_LIBRARIES} ${LIBHWLOC_LIBRARIES})
    add_umf_test(
        NAME memspace_lowest_latency
        SRCS memspaces/memspace_lowest_latency.cpp
        LIBS ${UMF_UTILS_FOR_TEST} ${LIBNUMA_LIBRARIES} ${LIBHWLOC_LIBRARIES})
    add_umf_test(
        NAME mempolicy
        SRCS memspaces/mempolicy.cpp
        LIBS ${LIBNUMA_LIBRARIES})
    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND UMF_BUILD_FUZZTESTS)
        add_subdirectory(fuzz)
    endif()
endif()

if(UMF_BUILD_GPU_TESTS AND UMF_BUILD_LEVEL_ZERO_PROVIDER)
    # we have two test binaries here that use the same sources, but differ in
    # the way they are linked to the Level Zero (statically or at runtime using
    # dlopen)
    add_umf_test(
        NAME provider_level_zero
        SRCS providers/provider_level_zero.cpp
        LIBS ${UMF_UTILS_FOR_TEST} ze_loader)
    target_include_directories(umf_test-provider_level_zero
                               PRIVATE ${LEVEL_ZERO_INCLUDE_DIRS})

    add_umf_test(
        NAME provider_level_zero_dlopen
        SRCS providers/provider_level_zero.cpp
        LIBS ${UMF_UTILS_FOR_TEST})
    target_compile_definitions(umf_test-provider_level_zero_dlopen
                               PUBLIC USE_DLOPEN=1)
    target_include_directories(umf_test-provider_level_zero_dlopen
                               PRIVATE ${LEVEL_ZERO_INCLUDE_DIRS})
endif()

if(UMF_BUILD_SHARED_LIBRARY)
    # if build as shared library, ba symbols won't be visible in tests
    set(BA_SOURCES_FOR_TEST ${BA_SOURCES})
endif()

add_umf_test(
    NAME base_alloc
    SRCS ${BA_SOURCES_FOR_TEST} test_base_alloc.cpp
    LIBS ${UMF_UTILS_FOR_TEST})
add_umf_test(
    NAME base_alloc_linear
    SRCS ${BA_SOURCES_FOR_TEST} test_base_alloc_linear.cpp
    LIBS ${UMF_UTILS_FOR_TEST})

add_umf_test(
    NAME base_alloc_global
    SRCS ${BA_SOURCES_FOR_TEST} pools/pool_base_alloc.cpp
         malloc_compliance_tests.cpp
    LIBS ${UMF_UTILS_FOR_TEST})

# tests for the proxy library
if(UMF_PROXY_LIB_ENABLED AND UMF_BUILD_SHARED_LIBRARY)
    add_umf_test(
        NAME proxy_lib_basic
        SRCS ${BA_SOURCES_FOR_TEST} test_proxy_lib.cpp
        LIBS ${UMF_UTILS_FOR_TEST} umf_proxy)

    # the memoryPool test run with the proxy library
    add_umf_test(
        NAME proxy_lib_memoryPool
        SRCS ${BA_SOURCES_FOR_TEST} memoryPoolAPI.cpp
             malloc_compliance_tests.cpp
        LIBS ${UMF_UTILS_FOR_TEST} umf_proxy)
    target_compile_definitions(umf_test-proxy_lib_memoryPool
                               PUBLIC UMF_PROXY_LIB_ENABLED=1)
endif()

add_umf_test(NAME ipc SRCS ipcAPI.cpp)

function(build_umf_ipc_test name)
    set(BASE_NAME ${name})

    foreach(loop_var IN ITEMS "producer" "consumer")
        set(EXEC_NAME umf_test-${BASE_NAME}_${loop_var})
        add_umf_executable(
            NAME ${EXEC_NAME}
            SRCS ${BASE_NAME}_${loop_var}.c
            LIBS umf)

        target_include_directories(
            ${EXEC_NAME} PRIVATE ${UMF_CMAKE_SOURCE_DIR}/src/utils
                                 ${UMF_CMAKE_SOURCE_DIR}/include)

        target_link_directories(${EXEC_NAME} PRIVATE ${LIBHWLOC_LIBRARY_DIRS})
    endforeach(loop_var)
endfunction()

function(add_umf_ipc_test script)
    set(TEST_NAME umf-${script})

    file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/${script}.sh
         DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

    add_test(
        NAME ${TEST_NAME}
        COMMAND ${script}.sh
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

    set_tests_properties(${TEST_NAME} PROPERTIES LABELS "umf")
    if(NOT UMF_TESTS_FAIL_ON_SKIP)
        set_tests_properties(${TEST_NAME} PROPERTIES SKIP_RETURN_CODE 125)
    endif()
endfunction()

if(LINUX)
    build_umf_ipc_test(ipc_os_prov)
    add_umf_ipc_test(ipc_os_prov_anon_fd)
    add_umf_ipc_test(ipc_os_prov_shm)
else()
    message(STATUS "IPC tests are supported on Linux only - skipping")
endif()

if(LINUX
   AND UMF_BUILD_SHARED_LIBRARY
   AND UMF_POOL_SCALABLE_ENABLED)
    add_umf_test(
        NAME init_teardown
        SRCS test_init_teardown.c
        LIBS dl)
    # append LD_LIBRARY_PATH to the libumf
    set_property(
        TEST umf-init_teardown
        PROPERTY ENVIRONMENT_MODIFICATION
                 "LD_LIBRARY_PATH=path_list_append:${CMAKE_BINARY_DIR}/lib")
endif()
