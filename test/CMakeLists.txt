# Copyright (C) 2022-2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED YES)

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

function(build_umf_test)
    # Parameters: * NAME - a name of the test * SRCS - source files * LIBS -
    # libraries to be linked with
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
        umf_test_common
        ${ARG_LIBS}
        GTest::gtest_main
        ${LIBS_OPTIONAL}
        umf)

    add_umf_executable(
        NAME ${TEST_TARGET_NAME}
        SRCS ${ARG_SRCS}
        LIBS ${TEST_LIBS})

    if(NOT MSVC)
        # Suppress 'cast discards const qualifier' warnings. Parametrized GTEST
        # tests retrieve arguments using 'GetParam()', which applies a 'const'
        # qualifier often discarded in the test scenarios.
        target_compile_options(${TEST_TARGET_NAME} PRIVATE -Wno-cast-qual)
    endif()

    target_link_directories(${TEST_TARGET_NAME} PRIVATE ${LIB_DIRS})

    target_include_directories(
        ${TEST_TARGET_NAME}
        PRIVATE ${UMF_CMAKE_SOURCE_DIR}/include
                ${UMF_CMAKE_SOURCE_DIR}/src
                ${UMF_CMAKE_SOURCE_DIR}/src/base_alloc
                ${UMF_CMAKE_SOURCE_DIR}/src/utils
                ${UMF_TEST_DIR}/common
                ${UMF_TEST_DIR})
endfunction()

function(add_umf_test)
    # Parameters: * NAME - a name of the test * SRCS - source files * LIBS -
    # libraries to be linked with
    set(oneValueArgs NAME)
    set(multiValueArgs SRCS LIBS)
    cmake_parse_arguments(
        ARG
        ""
        "${oneValueArgs}"
        "${multiValueArgs}"
        ${ARGN})

    build_umf_test(
        NAME
        ${ARG_NAME}
        SRCS
        ${ARG_SRCS}
        LIBS
        ${ARG_LIBS})

    set(TEST_NAME umf-${ARG_NAME})
    set(TEST_TARGET_NAME umf_test-${ARG_NAME})

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

if(UMF_BUILD_SHARED_LIBRARY)
    # if build as shared library, utils symbols won't be visible in tests
    set(UMF_UTILS_FOR_TEST umf_utils)
    if(LINUX OR MACOSX)
        set(UMF_UTILS_SOURCES
            ../src/utils/utils_common.c ../src/utils/utils_posix_common.c
            ../src/utils/utils_posix_concurrency.c)
        if(LINUX)
            set(UMF_UTILS_SOURCES ${UMF_UTILS_SOURCES}
                                  ../src/utils/utils_linux_common.c)
            set(UMF_LOGGER_LIBS rt) # librt for shm_open()
        elseif(MACOSX)
            set(UMF_UTILS_SOURCES ${UMF_UTILS_SOURCES}
                                  ../src/utils/utils_macosx_common.c)
        endif()
    elseif(WINDOWS)
        set(UMF_UTILS_SOURCES
            ../src/utils/utils_common.c ../src/utils/utils_windows_common.c
            ../src/utils/utils_windows_concurrency.c)
    endif()
endif()

add_umf_test(NAME base SRCS base.cpp)
add_umf_test(
    NAME memoryPool
    SRCS memoryPoolAPI.cpp malloc_compliance_tests.cpp
    LIBS ${UMF_UTILS_FOR_TEST})
add_umf_test(NAME memoryProvider SRCS memoryProviderAPI.cpp)
add_umf_test(
    NAME logger
    SRCS utils/utils_log.cpp ${UMF_UTILS_SOURCES}
    LIBS ${UMF_LOGGER_LIBS})

add_umf_test(
    NAME utils_common
    SRCS utils/utils.cpp
    LIBS ${UMF_UTILS_FOR_TEST})

add_umf_test(NAME provider_coarse SRCS provider_coarse.cpp)

if(UMF_BUILD_LIBUMF_POOL_DISJOINT)
    add_umf_test(
        NAME disjointPool
        SRCS pools/disjoint_pool.cpp malloc_compliance_tests.cpp
        LIBS disjoint_pool)
    add_umf_test(
        NAME c_api_disjoint_pool
        SRCS c_api/disjoint_pool.c
        LIBS disjoint_pool)
    add_umf_test(
        NAME disjointCoarseMallocPool
        SRCS disjointCoarseMallocPool.cpp
        LIBS disjoint_pool)
endif()

if(UMF_BUILD_LIBUMF_POOL_DISJOINT
   AND UMF_POOL_JEMALLOC_ENABLED
   AND UMF_POOL_SCALABLE_ENABLED
   AND (NOT UMF_DISABLE_HWLOC))
    add_umf_test(
        NAME c_api_multi_pool
        SRCS c_api/multi_pool.c
        LIBS disjoint_pool jemalloc_pool ${JEMALLOC_LIBRARIES})
endif()

if(UMF_POOL_JEMALLOC_ENABLED AND (NOT UMF_DISABLE_HWLOC))
    add_umf_test(
        NAME jemalloc_pool
        SRCS pools/jemalloc_pool.cpp malloc_compliance_tests.cpp
        LIBS jemalloc_pool)
endif()

if(UMF_POOL_SCALABLE_ENABLED AND (NOT UMF_DISABLE_HWLOC))
    add_umf_test(NAME scalable_pool SRCS pools/scalable_pool.cpp
                                         malloc_compliance_tests.cpp)
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
        SRCS provider_os_memory.cpp
        LIBS ${UMF_UTILS_FOR_TEST})
    if(UMF_BUILD_LIBUMF_POOL_DISJOINT)
        target_compile_definitions(umf_test-provider_os_memory
                                   PRIVATE UMF_POOL_DISJOINT_ENABLED=1)
        target_link_libraries(umf_test-provider_os_memory PRIVATE disjoint_pool)
    endif()

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
    add_umf_test(
        NAME memspace
        SRCS memspaces/memspace.cpp
        LIBS ${LIBNUMA_LIBRARIES})
    add_umf_test(
        NAME memtarget
        SRCS memspaces/memtarget.cpp
        LIBS ${LIBNUMA_LIBRARIES} ${LIBHWLOC_LIBRARIES})
    add_umf_test(
        NAME provider_devdax_memory
        SRCS provider_devdax_memory.cpp
        LIBS ${UMF_UTILS_FOR_TEST})
    add_umf_test(
        NAME provider_file_memory
        SRCS provider_file_memory.cpp
        LIBS ${UMF_UTILS_FOR_TEST})

    # This test requires Linux-only file memory provider
    if(UMF_POOL_JEMALLOC_ENABLED)
        add_umf_test(
            NAME jemalloc_coarse_file
            SRCS pools/jemalloc_coarse_file.cpp malloc_compliance_tests.cpp
            LIBS jemalloc_pool)
        add_umf_test(
            NAME jemalloc_coarse_devdax
            SRCS pools/jemalloc_coarse_devdax.cpp malloc_compliance_tests.cpp
            LIBS jemalloc_pool)
    endif()

    # This test requires Linux-only file memory provider
    if(UMF_POOL_SCALABLE_ENABLED)
        add_umf_test(
            NAME scalable_coarse_file SRCS pools/scalable_coarse_file.cpp
                                           malloc_compliance_tests.cpp)
        add_umf_test(
            NAME scalable_coarse_devdax SRCS pools/scalable_coarse_devdax.cpp
                                             malloc_compliance_tests.cpp)
    endif()

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
        SRCS providers/provider_level_zero.cpp providers/level_zero_helpers.cpp
        LIBS ${UMF_UTILS_FOR_TEST} ze_loader)
    target_include_directories(umf_test-provider_level_zero
                               PRIVATE ${LEVEL_ZERO_INCLUDE_DIRS})

    add_umf_test(
        NAME provider_level_zero_dlopen
        SRCS providers/provider_level_zero.cpp providers/level_zero_helpers.cpp
        LIBS ${UMF_UTILS_FOR_TEST})
    target_compile_definitions(umf_test-provider_level_zero_dlopen
                               PUBLIC USE_DLOPEN=1)
    target_include_directories(umf_test-provider_level_zero_dlopen
                               PRIVATE ${LEVEL_ZERO_INCLUDE_DIRS})
endif()

if(UMF_BUILD_GPU_TESTS AND UMF_BUILD_CUDA_PROVIDER)
    if(UMF_CUDA_ENABLED)
        # we have two test binaries here that use the same sources, but differ
        # in the way they are linked to the CUDA (statically or at runtime using
        # dlopen)
        add_umf_test(
            NAME provider_cuda
            SRCS providers/provider_cuda.cpp providers/cuda_helpers.cpp
            LIBS ${UMF_UTILS_FOR_TEST} cuda)
        target_include_directories(umf_test-provider_cuda
                                   PRIVATE ${CUDA_INCLUDE_DIRS})
        target_link_directories(umf_test-provider_cuda PRIVATE
                                ${CUDA_LIBRARY_DIRS})

        add_umf_test(
            NAME provider_cuda_dlopen
            SRCS providers/provider_cuda.cpp providers/cuda_helpers.cpp
            LIBS ${UMF_UTILS_FOR_TEST})
        target_compile_definitions(umf_test-provider_cuda_dlopen
                                   PUBLIC USE_DLOPEN=1)
        target_include_directories(umf_test-provider_cuda_dlopen
                                   PRIVATE ${CUDA_INCLUDE_DIRS})
    else()
        message(
            STATUS
                "CUDA provdier tests requires CUDA libraries to be installed and added to the default library search path - skipping"
        )
    endif()
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
if(UMF_PROXY_LIB_ENABLED
   AND UMF_BUILD_SHARED_LIBRARY
   AND NOT UMF_DISABLE_HWLOC
   AND NOT UMF_LINK_HWLOC_STATICALLY)
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

function(add_umf_ipc_test)
    # Parameters: * TEST - a name of the test * SRC_DIR - source files directory
    # path
    set(oneValueArgs TEST SRC_DIR)
    cmake_parse_arguments(
        ARG
        ""
        "${oneValueArgs}"
        ""
        ${ARGN})

    set(TEST_NAME umf-${ARG_TEST})

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
            NAME
            ipc_os_prov_consumer
            SRCS
            ipc_os_prov_consumer.c
            common/ipc_common.c
            common/ipc_os_prov_common.c)
        build_umf_test(
            NAME
            ipc_os_prov_producer
            SRCS
            ipc_os_prov_producer.c
            common/ipc_common.c
            common/ipc_os_prov_common.c)
        add_umf_ipc_test(TEST ipc_os_prov_anon_fd)
        add_umf_ipc_test(TEST ipc_os_prov_shm)

        build_umf_test(
            NAME
            ipc_devdax_prov_consumer
            SRCS
            ipc_devdax_prov_consumer.c
            common/ipc_common.c
            common/ipc_os_prov_common.c)
        build_umf_test(
            NAME
            ipc_devdax_prov_producer
            SRCS
            ipc_devdax_prov_producer.c
            common/ipc_common.c
            common/ipc_os_prov_common.c)
        add_umf_ipc_test(TEST ipc_devdax_prov)

        build_umf_test(
            NAME
            ipc_file_prov_consumer
            SRCS
            ipc_file_prov_consumer.c
            common/ipc_common.c
            common/ipc_os_prov_common.c)
        build_umf_test(
            NAME
            ipc_file_prov_producer
            SRCS
            ipc_file_prov_producer.c
            common/ipc_common.c
            common/ipc_os_prov_common.c)
        add_umf_ipc_test(TEST ipc_file_prov)
        add_umf_ipc_test(TEST ipc_file_prov_fsdax)
    endif()

    # TODO add IPC tests for CUDA

    if(UMF_BUILD_GPU_TESTS
       AND UMF_BUILD_LEVEL_ZERO_PROVIDER
       AND UMF_BUILD_LIBUMF_POOL_DISJOINT)
        build_umf_test(
            NAME
            ipc_level_zero_prov_consumer
            SRCS
            providers/ipc_level_zero_prov_consumer.c
            common/ipc_common.c
            providers/ipc_level_zero_prov_common.c
            providers/level_zero_helpers.cpp
            LIBS
            ze_loader
            disjoint_pool
            ${UMF_UTILS_FOR_TEST})
        build_umf_test(
            NAME
            ipc_level_zero_prov_producer
            SRCS
            providers/ipc_level_zero_prov_producer.c
            common/ipc_common.c
            providers/ipc_level_zero_prov_common.c
            providers/level_zero_helpers.cpp
            LIBS
            ze_loader
            disjoint_pool
            ${UMF_UTILS_FOR_TEST})
        target_include_directories(umf_test-ipc_level_zero_prov_producer
                                   PRIVATE ${LEVEL_ZERO_INCLUDE_DIRS})
        target_include_directories(umf_test-ipc_level_zero_prov_consumer
                                   PRIVATE ${LEVEL_ZERO_INCLUDE_DIRS})
        add_umf_ipc_test(TEST ipc_level_zero_prov SRC_DIR providers)
    endif()

    if(UMF_BUILD_GPU_TESTS
       AND UMF_BUILD_CUDA_PROVIDER
       AND UMF_BUILD_LIBUMF_POOL_DISJOINT)
        build_umf_test(
            NAME
            ipc_cuda_prov_consumer
            SRCS
            providers/ipc_cuda_prov_consumer.c
            common/ipc_common.c
            providers/ipc_cuda_prov_common.c
            providers/cuda_helpers.cpp
            LIBS
            cuda
            disjoint_pool
            ${UMF_UTILS_FOR_TEST})
        build_umf_test(
            NAME
            ipc_cuda_prov_producer
            SRCS
            providers/ipc_cuda_prov_producer.c
            common/ipc_common.c
            providers/ipc_cuda_prov_common.c
            providers/cuda_helpers.cpp
            LIBS
            cuda
            disjoint_pool
            ${UMF_UTILS_FOR_TEST})
        target_include_directories(umf_test-ipc_cuda_prov_producer
                                   PRIVATE ${CUDA_INCLUDE_DIRS})
        target_include_directories(umf_test-ipc_cuda_prov_consumer
                                   PRIVATE ${CUDA_INCLUDE_DIRS})
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
        TEST umf-init_teardown
        PROPERTY ENVIRONMENT_MODIFICATION
                 "LD_LIBRARY_PATH=path_list_append:${CMAKE_BINARY_DIR}/lib")
endif()

# Tests of examples as standalone projects. TODO: enable this for Windows (maybe
# replace test_examples.sh with CMake script?)
if(LINUX
   AND UMF_BUILD_SHARED_LIBRARY
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

    if(UMF_BUILD_GPU_EXAMPLES
       AND UMF_BUILD_LIBUMF_POOL_DISJOINT
       AND UMF_BUILD_LEVEL_ZERO_PROVIDER)
        set(EXAMPLES ${EXAMPLES} level_zero_shared_memory)
    else()
        message(
            STATUS
                "GPU level zero shared memory example requires UMF_BUILD_GPU_EXAMPLES, "
                "UMF_BUILD_LEVEL_ZERO_PROVIDER and UMF_BUILD_LIBUMF_POOL_DISJOINT "
                "to be turned ON - skipping")
    endif()

    if(UMF_BUILD_GPU_EXAMPLES
       AND UMF_BUILD_LIBUMF_POOL_DISJOINT
       AND UMF_BUILD_CUDA_PROVIDER
       AND UMF_CUDA_ENABLED)
        set(EXAMPLES ${EXAMPLES} cuda_shared_memory)
    else()
        message(
            STATUS
                "GPU CUDA shared memory example requires UMF_BUILD_GPU_EXAMPLES, "
                "UMF_BUILD_CUDA_PROVIDER, UMF_BUILD_LIBUMF_POOL_DISJOINT "
                "to be turned ON and installed CUDA libraries - skipping")
    endif()

    # TODO add IPC examples for CUDA
    if(UMF_BUILD_GPU_EXAMPLES
       AND UMF_BUILD_LIBUMF_POOL_DISJOINT
       AND UMF_BUILD_LEVEL_ZERO_PROVIDER)
        set(EXAMPLES ${EXAMPLES} ipc_level_zero)
    else()
        message(
            STATUS
                "IPC Level 0 example requires UMF_BUILD_GPU_EXAMPLES, UMF_BUILD_LEVEL_ZERO_PROVIDER and UMF_BUILD_LIBUMF_POOL_DISJOINT to be turned ON - skipping"
        )
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
                "The dram_and_fsdax example is supported on Linux only and requires UMF_BUILD_LIBUMF_POOL_JEMALLOC to be turned ON - skipping"
        )
    endif()

    if(EXAMPLES AND NOT UMF_DISABLE_HWLOC)
        set(STANDALONE_CMAKE_OPTIONS
            "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER} -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
        )
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
