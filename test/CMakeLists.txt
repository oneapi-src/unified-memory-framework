# Copyright (C) 2022-2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED YES)

if(CMAKE_C_COMPILER_ID STREQUAL "IntelLLVM")
    # Compiler dependencies needs to be in library path or to be linked
    # statically
    add_link_options(-static-intel)
endif()

include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.15.2)

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
set(UMF_UTILS_DIR ${UMF_CMAKE_SOURCE_DIR}/src/utils)

function(build_umf_test)
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

    set(TEST_NAME test_${ARG_NAME})
    set(TEST_TARGET_NAME test_${ARG_NAME})

    set(LIB_DIRS ${LIB_DIRS} ${LIBHWLOC_LIBRARY_DIRS})

    if(UMF_CUDA_ENABLED)
        set(INC_DIRS ${INC_DIRS} ${CUDA_INCLUDE_DIRS})
        set(LIB_DIRS ${LIB_DIRS} ${CUDA_LIBRARY_DIRS})
    endif()

    if(UMF_LEVEL_ZERO_ENABLED)
        set(INC_DIRS ${INC_DIRS} ${LEVEL_ZERO_INCLUDE_DIRS})
        set(LIB_DIRS ${LIB_DIRS} ${ZE_LOADER_LIBRARY_DIRS})
    endif()

    if(NOT UMF_DISABLE_HWLOC)
        set(INC_DIRS ${INC_DIRS} ${LIBHWLOC_INCLUDE_DIRS})
    endif()

    if(UMF_POOL_JEMALLOC_ENABLED)
        set(CPL_DEFS ${CPL_DEFS} UMF_POOL_JEMALLOC_ENABLED=1)
    endif()

    if(UMF_POOL_SCALABLE_ENABLED)
        set(CPL_DEFS ${CPL_DEFS} UMF_POOL_SCALABLE_ENABLED=1)
    endif()

    set(TEST_LIBS
        umf_test_common
        ${ARG_LIBS}
        GTest::gtest_main
        ${LIBS_OPTIONAL}
        umf)

    add_umf_executable(
        NAME ${TEST_TARGET_NAME}
        SRCS ${ARG_SRCS}
        LIBS ${TEST_LIBS})

    target_compile_definitions(${TEST_TARGET_NAME} PRIVATE ${CPL_DEFS})

    if(NOT MSVC)
        # Suppress 'cast discards const qualifier' warnings. Parametrized GTEST
        # tests retrieve arguments using 'GetParam()', which applies a 'const'
        # qualifier often discarded in the test scenarios.
        target_compile_options(${TEST_TARGET_NAME} PRIVATE -Wno-cast-qual)

        if(UMF_DEVELOPER_MODE)
            target_compile_options(${TEST_TARGET_NAME} PRIVATE -Werror)
        endif()
    endif()

    target_link_directories(${TEST_TARGET_NAME} PRIVATE ${LIB_DIRS})

    target_include_directories(
        ${TEST_TARGET_NAME}
        PRIVATE ${UMF_CMAKE_SOURCE_DIR}/include
                ${UMF_CMAKE_SOURCE_DIR}/src
                ${UMF_CMAKE_SOURCE_DIR}/src/base_alloc
                ${UMF_CMAKE_SOURCE_DIR}/src/coarse
                ${UMF_CMAKE_SOURCE_DIR}/src/utils
                ${UMF_TEST_DIR}/common
                ${UMF_TEST_DIR}
                ${INC_DIRS})
endfunction()

function(add_umf_test)
    # Parameters:
    #
    # * NAME - a name of the test
    # * SRCS - source files
    # * LIBS - libraries to be linked with
    # * ENVS - environment variables
    set(oneValueArgs NAME)
    set(multiValueArgs SRCS LIBS ENVS)
    cmake_parse_arguments(
        ARG
        ""
        "${oneValueArgs}"
        "${multiValueArgs}"
        ${ARGN})

    build_umf_test(
        NAME ${ARG_NAME}
        SRCS ${ARG_SRCS}
        LIBS ${ARG_LIBS})

    set(TEST_NAME test_${ARG_NAME})
    set(TEST_TARGET_NAME test_${ARG_NAME})

    add_test(
        NAME ${TEST_NAME}
        COMMAND ${TEST_TARGET_NAME}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

    set_tests_properties(${TEST_NAME} PROPERTIES LABELS "umf")
    if(ARG_ENVS)
        set_tests_properties(${TEST_NAME} PROPERTIES ENVIRONMENT ${ARG_ENVS})
    endif()

    if(WINDOWS)
        # add PATH to DLL on Windows
        set(DLL_PATH_LIST
            "${DLL_PATH_LIST};PATH=path_list_append:${CMAKE_BINARY_DIR}/bin/;PATH=path_list_append:${CMAKE_BINARY_DIR}/bin/$<CONFIG>/"
        )

        # append PATH to DLLs
        set_property(TEST ${TEST_NAME} PROPERTY ENVIRONMENT_MODIFICATION
                                                "${DLL_PATH_LIST}")
    endif()
endfunction()

add_subdirectory(common)

if(UMF_BUILD_SHARED_LIBRARY)
    # if build as shared library, utils symbols won't be visible in tests
    set(UMF_UTILS_FOR_TEST umf_utils)
    if(LINUX OR MACOSX)
        set(UMF_UTILS_SOURCES
            ${UMF_UTILS_DIR}/utils_common.c
            ${UMF_UTILS_DIR}/utils_posix_common.c
            ${UMF_UTILS_DIR}/utils_posix_concurrency.c)
        if(LINUX)
            set(UMF_UTILS_SOURCES ${UMF_UTILS_SOURCES}
                                  ${UMF_UTILS_DIR}/utils_linux_common.c)
            set(UMF_LOGGER_LIBS rt) # librt for shm_open()
        elseif(MACOSX)
            set(UMF_UTILS_SOURCES ${UMF_UTILS_SOURCES}
                                  ${UMF_UTILS_DIR}/utils_macosx_common.c)
        endif()
    elseif(WINDOWS)
        set(UMF_UTILS_SOURCES
            ${UMF_UTILS_DIR}/utils_common.c
            ${UMF_UTILS_DIR}/utils_windows_common.c
            ${UMF_UTILS_DIR}/utils_windows_concurrency.c)
    endif()
endif()

if(UMF_BUILD_SHARED_LIBRARY)
    # if build as shared library, ba symbols won't be visible in tests
    set(BA_SOURCES_FOR_TEST ${BA_SOURCES})
endif()

add_umf_test(NAME base SRCS base.cpp)
add_umf_test(
    NAME memoryPool
    SRCS memoryPoolAPI.cpp malloc_compliance_tests.cpp ${BA_SOURCES_FOR_TEST}
    LIBS ${UMF_UTILS_FOR_TEST})
add_umf_test(
    NAME memoryProvider
    SRCS memoryProviderAPI.cpp ${BA_SOURCES_FOR_TEST}
    LIBS ${UMF_UTILS_FOR_TEST})
add_umf_test(
    NAME logger
    SRCS utils/utils_log.cpp ${UMF_UTILS_SOURCES}
    LIBS ${UMF_LOGGER_LIBS})

add_umf_test(
    NAME ctl_unittest
    SRCS ctl/ctl_unittest.cpp ctl/ctl_debug.c ../src/ctl/ctl.c
         ${BA_SOURCES_FOR_TEST}
    LIBS ${UMF_UTILS_FOR_TEST})

add_umf_test(
    NAME ctl_api
    SRCS ctl/ctl_api.cpp ${BA_SOURCES_FOR_TEST}
    LIBS ${UMF_UTILS_FOR_TEST})

add_umf_test(
    NAME utils_common
    SRCS utils/utils.cpp
    LIBS ${UMF_UTILS_FOR_TEST})

if(LINUX)
    add_umf_test(
        NAME utils_linux_common
        SRCS utils/utils_linux.cpp
        LIBS ${UMF_UTILS_FOR_TEST})
endif()

add_umf_test(
    NAME coarse_lib
    SRCS coarse_lib.cpp ${BA_SOURCES_FOR_TEST}
    LIBS ${UMF_UTILS_FOR_TEST} coarse)

add_umf_test(
    NAME disjoint_pool
    SRCS pools/disjoint_pool.cpp malloc_compliance_tests.cpp
         ${BA_SOURCES_FOR_TEST} ${UMF_CMAKE_SOURCE_DIR}/src/critnib/critnib.c
    LIBS ${UMF_UTILS_FOR_TEST})

add_umf_test(
    NAME c_api_disjoint_pool
    SRCS c_api/disjoint_pool.c ${BA_SOURCES_FOR_TEST}
    LIBS ${UMF_UTILS_FOR_TEST})

if(LINUX AND (NOT UMF_DISABLE_HWLOC))
    # this test uses the file provider
    add_umf_test(
        NAME disjoint_pool_file_prov
        SRCS disjoint_pool_file_prov.cpp ${BA_SOURCES_FOR_TEST}
        LIBS ${UMF_UTILS_FOR_TEST})
endif()

if(UMF_POOL_JEMALLOC_ENABLED
   AND UMF_POOL_SCALABLE_ENABLED
   AND (NOT UMF_DISABLE_HWLOC))
    add_umf_test(NAME c_api_multi_pool SRCS c_api/multi_pool.c)
endif()

if(UMF_POOL_JEMALLOC_ENABLED AND (NOT UMF_DISABLE_HWLOC))
    add_umf_test(
        NAME jemalloc_pool
        SRCS pools/jemalloc_pool.cpp malloc_compliance_tests.cpp
             ${BA_SOURCES_FOR_TEST}
        LIBS ${UMF_UTILS_FOR_TEST})
endif()

if(UMF_POOL_SCALABLE_ENABLED AND (NOT UMF_DISABLE_HWLOC))
    add_umf_test(
        NAME scalable_pool
        SRCS pools/scalable_pool.cpp malloc_compliance_tests.cpp
             ${BA_SOURCES_FOR_TEST}
        LIBS ${UMF_UTILS_FOR_TEST})
endif()

if(LINUX AND (NOT UMF_DISABLE_HWLOC)) # OS-specific functions are implemented
                                      # only for Linux now
    if(PkgConfig_FOUND)
        pkg_check_modules(LIBNUMA numa)
    endif()
    if(NOT LIBNUMA_FOUND)
        find_package(LIBNUMA REQUIRED numa)
    endif()

    add_umf_test(
        NAME provider_os_memory
        SRCS provider_os_memory.cpp ${BA_SOURCES_FOR_TEST}
        LIBS ${UMF_UTILS_FOR_TEST})
    add_umf_test(
        NAME provider_os_memory_multiple_numa_nodes
        SRCS provider_os_memory_multiple_numa_nodes.cpp
        LIBS ${UMF_UTILS_FOR_TEST} ${LIBNUMA_LIBRARIES})
    add_umf_test(
        NAME memspace_numa
        SRCS memspaces/memspace_numa.cpp
        LIBS ${LIBNUMA_LIBRARIES} ${UMF_HWLOC_NAME})
    add_umf_test(
        NAME provider_os_memory_config
        SRCS provider_os_memory_config.cpp
        LIBS ${UMF_UTILS_FOR_TEST} ${LIBNUMA_LIBRARIES} ${UMF_HWLOC_NAME})
    add_umf_test(
        NAME memspace_host_all
        SRCS memspaces/memspace_host_all.cpp
        LIBS ${UMF_UTILS_FOR_TEST} ${LIBNUMA_LIBRARIES} ${UMF_HWLOC_NAME})
    add_umf_test(
        NAME memspace_highest_capacity
        SRCS memspaces/memspace_highest_capacity.cpp
        LIBS ${UMF_UTILS_FOR_TEST} ${LIBNUMA_LIBRARIES} ${UMF_HWLOC_NAME})
    add_umf_test(
        NAME memspace_highest_bandwidth
        SRCS memspaces/memspace_highest_bandwidth.cpp
        LIBS ${UMF_UTILS_FOR_TEST} ${LIBNUMA_LIBRARIES} ${UMF_HWLOC_NAME})
    add_umf_test(
        NAME memspace_lowest_latency
        SRCS memspaces/memspace_lowest_latency.cpp
        LIBS ${UMF_UTILS_FOR_TEST} ${LIBNUMA_LIBRARIES} ${UMF_HWLOC_NAME})
    add_umf_test(
        NAME mempolicy
        SRCS memspaces/mempolicy.cpp
        LIBS ${LIBNUMA_LIBRARIES})
    add_umf_test(
        NAME memspace
        SRCS memspaces/memspace.cpp
        LIBS ${LIBNUMA_LIBRARIES})
    add_umf_test(
        NAME memtarget
        SRCS memspaces/memtarget.cpp
        LIBS ${LIBNUMA_LIBRARIES} ${UMF_HWLOC_NAME})
    add_umf_test(
        NAME provider_devdax_memory
        SRCS provider_devdax_memory.cpp
        LIBS ${UMF_UTILS_FOR_TEST})
    add_umf_test(
        NAME provider_devdax_memory_ipc
        SRCS provider_devdax_memory_ipc.cpp ${BA_SOURCES_FOR_TEST}
        LIBS ${UMF_UTILS_FOR_TEST})
    add_umf_test(
        NAME provider_file_memory
        SRCS provider_file_memory.cpp
        LIBS ${UMF_UTILS_FOR_TEST})
    add_umf_test(
        NAME provider_file_memory_ipc
        SRCS provider_file_memory_ipc.cpp ${BA_SOURCES_FOR_TEST}
        LIBS ${UMF_UTILS_FOR_TEST})
    add_umf_test(
        NAME provider_fixed_memory
        SRCS provider_fixed_memory.cpp
        LIBS ${UMF_UTILS_FOR_TEST})
    add_umf_test(
        NAME provider_tracking
        SRCS provider_tracking.cpp
        LIBS ${UMF_UTILS_FOR_TEST})
    add_umf_test(
        NAME provider_tracking_fixture_tests
        SRCS provider_tracking_fixture_tests.cpp malloc_compliance_tests.cpp
             ${BA_SOURCES_FOR_TEST}
        LIBS ${UMF_UTILS_FOR_TEST})

    # This test requires Linux-only file memory provider
    if(UMF_POOL_JEMALLOC_ENABLED)
        add_umf_test(
            NAME jemalloc_coarse_file
            SRCS pools/jemalloc_coarse_file.cpp malloc_compliance_tests.cpp
                 ${BA_SOURCES_FOR_TEST}
            LIBS ${UMF_UTILS_FOR_TEST})
        add_umf_test(
            NAME jemalloc_coarse_devdax
            SRCS pools/jemalloc_coarse_devdax.cpp malloc_compliance_tests.cpp
                 ${BA_SOURCES_FOR_TEST}
            LIBS ${UMF_UTILS_FOR_TEST})
    endif()

    # This test requires Linux-only file memory provider
    if(UMF_POOL_SCALABLE_ENABLED)
        add_umf_test(
            NAME scalable_coarse_file
            SRCS pools/scalable_coarse_file.cpp malloc_compliance_tests.cpp
                 ${BA_SOURCES_FOR_TEST}
            LIBS ${UMF_UTILS_FOR_TEST})
        add_umf_test(
            NAME scalable_coarse_devdax
            SRCS pools/scalable_coarse_devdax.cpp malloc_compliance_tests.cpp
                 ${BA_SOURCES_FOR_TEST}
            LIBS ${UMF_UTILS_FOR_TEST})
    endif()

    if(UMF_BUILD_FUZZTESTS)
        add_subdirectory(fuzz)
    endif()
else()
    add_umf_test(
        NAME provider_file_memory_not_impl
        SRCS provider_file_memory_not_impl.cpp
        LIBS ${UMF_UTILS_FOR_TEST})
    add_umf_test(
        NAME provider_devdax_memory_not_impl
        SRCS provider_devdax_memory_not_impl.cpp
        LIBS ${UMF_UTILS_FOR_TEST})
endif()

if(UMF_DISABLE_HWLOC)
    add_umf_test(
        NAME provider_os_memory_not_impl
        SRCS provider_os_memory_not_impl.cpp
        LIBS ${UMF_UTILS_FOR_TEST})
endif()

if(UMF_BUILD_GPU_TESTS AND UMF_LEVEL_ZERO_ENABLED)
    # we have two test binaries here that use the same sources, but differ in
    # the way they are linked to the Level Zero (statically or at runtime using
    # dlopen)
    add_umf_test(
        NAME provider_level_zero
        SRCS providers/provider_level_zero.cpp
             ${UMF_UTILS_DIR}/utils_level_zero.cpp ${BA_SOURCES_FOR_TEST}
        LIBS ${UMF_UTILS_FOR_TEST} ze_loader)

    add_umf_test(
        NAME provider_level_zero_dlopen_global
        SRCS providers/provider_level_zero.cpp
             ${UMF_UTILS_DIR}/utils_level_zero.cpp ${BA_SOURCES_FOR_TEST}
        LIBS ${UMF_UTILS_FOR_TEST})
    target_compile_definitions(test_provider_level_zero_dlopen_global
                               PUBLIC USE_DLOPEN=1 OPEN_ZE_LIBRARY_GLOBAL=1)

    add_umf_test(
        NAME provider_level_zero_dlopen_local
        SRCS providers/provider_level_zero.cpp
             ${UMF_UTILS_DIR}/utils_level_zero.cpp ${BA_SOURCES_FOR_TEST}
        LIBS ${UMF_UTILS_FOR_TEST})
    target_compile_definitions(test_provider_level_zero_dlopen_local
                               PUBLIC USE_DLOPEN=1 OPEN_ZE_LIBRARY_GLOBAL=0)
endif()

if(NOT UMF_BUILD_LEVEL_ZERO_PROVIDER)
    add_umf_test(
        NAME provider_level_zero_not_impl
        SRCS providers/provider_level_zero_not_impl.cpp
        LIBS ${UMF_UTILS_FOR_TEST})
endif()

if(UMF_BUILD_GPU_TESTS AND UMF_BUILD_CUDA_PROVIDER)
    if(UMF_CUDA_ENABLED)
        # we have two test binaries here that use the same sources, but differ
        # in the way they are linked to the CUDA (statically or at runtime using
        # dlopen)
        add_umf_test(
            NAME provider_cuda
            SRCS providers/provider_cuda.cpp providers/cuda_helpers.cpp
                 ${BA_SOURCES_FOR_TEST}
            LIBS ${UMF_UTILS_FOR_TEST} cuda)

        add_umf_test(
            NAME provider_cuda_dlopen_global
            SRCS providers/provider_cuda.cpp providers/cuda_helpers.cpp
                 ${BA_SOURCES_FOR_TEST}
            LIBS ${UMF_UTILS_FOR_TEST})
        target_compile_definitions(test_provider_cuda_dlopen_global
                                   PUBLIC USE_DLOPEN=1 OPEN_CU_LIBRARY_GLOBAL=1)

        add_umf_test(
            NAME provider_cuda_dlopen_local
            SRCS providers/provider_cuda.cpp providers/cuda_helpers.cpp
                 ${BA_SOURCES_FOR_TEST}
            LIBS ${UMF_UTILS_FOR_TEST})
        target_compile_definitions(test_provider_cuda_dlopen_local
                                   PUBLIC USE_DLOPEN=1 OPEN_CU_LIBRARY_GLOBAL=0)
    else()
        message(
            STATUS
                "CUDA provdier tests requires CUDA libraries to be installed and added to the default library search path - skipping"
        )
    endif()
endif()

if(NOT UMF_BUILD_CUDA_PROVIDER)
    add_umf_test(
        NAME provider_cuda_not_impl
        SRCS providers/provider_cuda_not_impl.cpp
        LIBS ${UMF_UTILS_FOR_TEST})
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

    # TODO enable this test on Windows
    if(LINUX)
        add_umf_test(
            NAME proxy_lib_size_threshold
            SRCS ${BA_SOURCES_FOR_TEST} test_proxy_lib_size_threshold.cpp
            LIBS ${UMF_UTILS_FOR_TEST} umf_proxy)
        set_property(TEST test_proxy_lib_size_threshold
                     PROPERTY ENVIRONMENT UMF_PROXY="size.threshold=64")
    endif()

    # the memoryPool test run with the proxy library
    add_umf_test(
        NAME proxy_lib_memoryPool
        SRCS ${BA_SOURCES_FOR_TEST} memoryPoolAPI.cpp
             malloc_compliance_tests.cpp
        LIBS ${UMF_UTILS_FOR_TEST} umf_proxy)
    target_compile_definitions(test_proxy_lib_memoryPool
                               PUBLIC UMF_PROXY_LIB_ENABLED=1)
endif()

add_umf_test(
    NAME ipc
    SRCS ipcAPI.cpp ${BA_SOURCES_FOR_TEST}
    LIBS ${UMF_UTILS_FOR_TEST})

add_umf_test(
    NAME ipc_max_opened_limit
    SRCS ipcAPI.cpp ${BA_SOURCES_FOR_TEST}
    LIBS ${UMF_UTILS_FOR_TEST}
    ENVS "UMF_MAX_OPENED_IPC_HANDLES=10")

add_umf_test(NAME ipc_negative SRCS ipc_negative.cpp)

function(add_umf_ipc_test)
    # Parameters:
    #
    # * TEST - a name of the test
    # * SRC_DIR - source files directory path
    set(oneValueArgs TEST SRC_DIR)
    cmake_parse_arguments(
        ARG
        ""
        "${oneValueArgs}"
        ""
        ${ARGN})

    set(TEST_NAME test_${ARG_TEST})

    if(DEFINED ARG_SRC_DIR)
        set(SRC_DIR ${ARG_SRC_DIR})
    else()
        set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR})
    endif()

    file(COPY ${SRC_DIR}/${ARG_TEST}.sh DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

    add_test(
        NAME ${TEST_NAME}
        COMMAND ${ARG_TEST}.sh
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

    set_tests_properties(${TEST_NAME} PROPERTIES LABELS "umf")
    set_tests_properties(${TEST_NAME} PROPERTIES TIMEOUT 60)
    if(NOT UMF_TESTS_FAIL_ON_SKIP)
        set_tests_properties(${TEST_NAME} PROPERTIES SKIP_RETURN_CODE 125)
    endif()
endfunction()

if(LINUX)
    if(NOT UMF_DISABLE_HWLOC AND UMF_POOL_SCALABLE_ENABLED)
        build_umf_test(
            NAME ipc_os_prov_consumer
            SRCS ipc_os_prov_consumer.c common/ipc_common.c
                 common/ipc_os_prov_common.c)
        build_umf_test(
            NAME ipc_os_prov_producer
            SRCS ipc_os_prov_producer.c common/ipc_common.c
                 common/ipc_os_prov_common.c)
        add_umf_ipc_test(TEST ipc_os_prov_anon_fd)
        add_umf_ipc_test(TEST ipc_os_prov_shm)

        if(UMF_PROXY_LIB_ENABLED AND UMF_BUILD_SHARED_LIBRARY)
            build_umf_test(
                NAME ipc_os_prov_proxy
                SRCS ipc_os_prov_proxy.c common/ipc_common.c
                LIBS ${UMF_UTILS_FOR_TEST})
            add_umf_ipc_test(TEST ipc_os_prov_proxy)
        endif()

        build_umf_test(
            NAME ipc_devdax_prov_consumer
            SRCS ipc_devdax_prov_consumer.c common/ipc_common.c
                 common/ipc_os_prov_common.c)
        build_umf_test(
            NAME ipc_devdax_prov_producer
            SRCS ipc_devdax_prov_producer.c common/ipc_common.c
                 common/ipc_os_prov_common.c)
        add_umf_ipc_test(TEST ipc_devdax_prov)

        build_umf_test(
            NAME ipc_file_prov_consumer
            SRCS ipc_file_prov_consumer.c common/ipc_common.c
                 common/ipc_os_prov_common.c)
        build_umf_test(
            NAME ipc_file_prov_producer
            SRCS ipc_file_prov_producer.c common/ipc_common.c
                 common/ipc_os_prov_common.c)
        add_umf_ipc_test(TEST ipc_file_prov)
        add_umf_ipc_test(TEST ipc_file_prov_fsdax)
    endif()

    # TODO add IPC tests for CUDA

    if(UMF_BUILD_GPU_TESTS AND UMF_LEVEL_ZERO_ENABLED)
        build_umf_test(
            NAME ipc_level_zero_prov_consumer
            SRCS providers/ipc_level_zero_prov_consumer.c common/ipc_common.c
                 providers/ipc_level_zero_prov_common.c
                 ${UMF_UTILS_DIR}/utils_level_zero.cpp
            LIBS ze_loader ${UMF_UTILS_FOR_TEST})
        build_umf_test(
            NAME ipc_level_zero_prov_producer
            SRCS providers/ipc_level_zero_prov_producer.c common/ipc_common.c
                 providers/ipc_level_zero_prov_common.c
                 ${UMF_UTILS_DIR}/utils_level_zero.cpp
            LIBS ze_loader ${UMF_UTILS_FOR_TEST})
        add_umf_ipc_test(TEST ipc_level_zero_prov SRC_DIR providers)
    endif()

    if(UMF_BUILD_GPU_TESTS AND UMF_BUILD_CUDA_PROVIDER)
        build_umf_test(
            NAME ipc_cuda_prov_consumer
            SRCS providers/ipc_cuda_prov_consumer.c common/ipc_common.c
                 providers/ipc_cuda_prov_common.c providers/cuda_helpers.cpp
            LIBS cuda ${UMF_UTILS_FOR_TEST})
        build_umf_test(
            NAME ipc_cuda_prov_producer
            SRCS providers/ipc_cuda_prov_producer.c common/ipc_common.c
                 providers/ipc_cuda_prov_common.c providers/cuda_helpers.cpp
            LIBS cuda ${UMF_UTILS_FOR_TEST})
        add_umf_ipc_test(TEST ipc_cuda_prov SRC_DIR providers)
    endif()
else()
    message(STATUS "IPC tests are supported on Linux only - skipping")
endif()

if(LINUX
   AND UMF_BUILD_SHARED_LIBRARY
   AND UMF_POOL_SCALABLE_ENABLED
   AND NOT UMF_DISABLE_HWLOC)
    add_umf_test(
        NAME init_teardown
        SRCS test_init_teardown.c
        LIBS dl)
    # append LD_LIBRARY_PATH to the libumf
    set_property(
        TEST test_init_teardown
        PROPERTY ENVIRONMENT_MODIFICATION
                 "LD_LIBRARY_PATH=path_list_append:${CMAKE_BINARY_DIR}/lib")
endif()

# Tests of examples as standalone projects. TODO: enable this for Windows (maybe
# replace test_examples.sh with CMake script?)
if(LINUX
   AND UMF_BUILD_SHARED_LIBRARY
   AND UMF_BUILD_EXAMPLES
   AND NOT
       (UMF_USE_ASAN
        OR UMF_USE_UBSAN
        OR UMF_USE_TSAN
        OR UMF_USE_MSAN
        OR UMF_USE_COVERAGE))

    set(EXAMPLES "")

    if(UMF_POOL_SCALABLE_ENABLED)
        set(EXAMPLES ${EXAMPLES} basic custom_file_provider)
    else()
        message(
            STATUS
                "The basic and custom_file_provider examples require TBB to be installed and added to the default library search path - skipping"
        )
    endif()

    if(LIBNUMA_LIBRARIES)
        set(EXAMPLES ${EXAMPLES} memspace_hmat memspace_numa)
    else()
        message(
            STATUS
                "The memspace_hmat and memspace_numa examples require libnuma to be installed and added to the default library search path - skipping"
        )
    endif()

    if(UMF_BUILD_GPU_EXAMPLES AND UMF_LEVEL_ZERO_ENABLED)
        set(EXAMPLES ${EXAMPLES} level_zero_shared_memory)
    else()
        message(
            STATUS
                "GPU level zero shared memory example requires UMF_BUILD_GPU_EXAMPLES and "
                "UMF_BUILD_LEVEL_ZERO_PROVIDER to be turned ON - skipping")
    endif()

    if(UMF_BUILD_GPU_EXAMPLES AND UMF_CUDA_ENABLED)
        set(EXAMPLES ${EXAMPLES} cuda_shared_memory)
    else()
        message(
            STATUS
                "GPU CUDA shared memory example requires UMF_BUILD_GPU_EXAMPLES "
                "and UMF_BUILD_CUDA_PROVIDER to be turned ON and installed CUDA "
                "libraries - skipping")
    endif()

    # TODO add IPC examples for CUDA
    if(UMF_BUILD_GPU_EXAMPLES AND UMF_LEVEL_ZERO_ENABLED)
        set(EXAMPLES ${EXAMPLES} ipc_level_zero)
    else()
        message(
            STATUS "IPC Level Zero example requires UMF_BUILD_GPU_EXAMPLES and "
                   "UMF_BUILD_LEVEL_ZERO_PROVIDER to be turned ON - skipping")
    endif()

    if(UMF_POOL_SCALABLE_ENABLED)
        set(EXAMPLES ${EXAMPLES} ipc_ipcapi)
    else()
        message(
            STATUS
                "IPC examples with UMF pool API are supported on Linux with TBB installed only - skipping"
        )
    endif()

    if(UMF_POOL_JEMALLOC_ENABLED)
        set(EXAMPLES ${EXAMPLES} dram_and_fsdax)
    else()
        message(
            STATUS
                "The dram_and_fsdax example is supported on Linux only and requires the jemalloc pool, but it is disabled - skipping"
        )
    endif()

    if(EXAMPLES AND NOT UMF_DISABLE_HWLOC)
        set(STANDALONE_CMAKE_OPTIONS
            "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER} -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
        )
        if(JEMALLOC_INCLUDE_DIRS)
            # add custom jemalloc installation
            set(STANDALONE_CMAKE_OPTIONS
                "${STANDALONE_CMAKE_OPTIONS} -DCMAKE_PREFIX_PATH=${JEMALLOC_INCLUDE_DIRS}/../"
            )
        endif()

        add_test(
            NAME umf-standalone_examples
            COMMAND
                ${UMF_CMAKE_SOURCE_DIR}/test/test_examples.sh
                ${UMF_CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR}
                ${CMAKE_CURRENT_BINARY_DIR}/umf_standalone_examples/install-dir
                "${CMAKE_INSTALL_PREFIX}" "${STANDALONE_CMAKE_OPTIONS}"
                ${EXAMPLES}
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
    endif()
endif()
