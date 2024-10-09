# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# NOTE: the basic example is always built, even if the TBB required by the
# Scalable Pool is not detected by CMake. If the TBB is not detected during the
# execution of the basic example, the user will receive a corresponding error
# message.
if(NOT UMF_POOL_SCALABLE_ENABLED)
    message(
        WARNING
            "The Basic Example is built but TBB required by Scalable Pool it "
            "uses was not found by CMake. Make sure TBB is added to the default "
            "library search path before running it.")
endif()
set(EXAMPLE_NAME umf_example_basic)

add_umf_executable(
    NAME ${EXAMPLE_NAME}
    SRCS basic/basic.c
    LIBS umf ${LIBHWLOC_LIBRARIES})

target_include_directories(
    ${EXAMPLE_NAME} PRIVATE ${UMF_CMAKE_SOURCE_DIR}/src/utils
                            ${UMF_CMAKE_SOURCE_DIR}/include)

target_link_directories(${EXAMPLE_NAME} PRIVATE ${LIBHWLOC_LIBRARY_DIRS})

if(UMF_POOL_SCALABLE_ENABLED)
    add_test(
        NAME ${EXAMPLE_NAME}
        COMMAND ${EXAMPLE_NAME}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

    set_tests_properties(${EXAMPLE_NAME} PROPERTIES LABELS "example")

    if(WINDOWS)
        # append PATH to DLLs
        set_property(TEST ${EXAMPLE_NAME} PROPERTY ENVIRONMENT_MODIFICATION
                                                   "${DLL_PATH_LIST}")
    endif()
endif()

if(UMF_BUILD_GPU_EXAMPLES
   AND UMF_BUILD_LIBUMF_POOL_DISJOINT
   AND UMF_BUILD_LEVEL_ZERO_PROVIDER)
    set(EXAMPLE_NAME umf_example_level_zero_shared_memory)

    add_umf_executable(
        NAME ${EXAMPLE_NAME}
        SRCS level_zero_shared_memory/level_zero_shared_memory.c
        LIBS disjoint_pool ze_loader umf)

    target_include_directories(
        ${EXAMPLE_NAME}
        PRIVATE ${LEVEL_ZERO_INCLUDE_DIRS} ${UMF_CMAKE_SOURCE_DIR}/src/utils
                ${UMF_CMAKE_SOURCE_DIR}/include
                ${UMF_CMAKE_SOURCE_DIR}/examples/common)

    target_link_directories(${EXAMPLE_NAME} PRIVATE ${LIBHWLOC_LIBRARY_DIRS})

    add_test(
        NAME ${EXAMPLE_NAME}
        COMMAND ${EXAMPLE_NAME}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

    set_tests_properties(${EXAMPLE_NAME} PROPERTIES LABELS "example")

    if(WINDOWS)
        # append PATH to DLLs
        set_property(TEST ${EXAMPLE_NAME} PROPERTY ENVIRONMENT_MODIFICATION
                                                   "${DLL_PATH_LIST}")
    endif()
else()
    message(STATUS "GPU Level Zero shared memory example requires "
                   "UMF_BUILD_GPU_EXAMPLES, UMF_BUILD_LEVEL_ZERO_PROVIDER and "
                   "UMF_BUILD_LIBUMF_POOL_DISJOINT to be turned ON - skipping")
endif()

if(UMF_BUILD_GPU_EXAMPLES
   AND UMF_BUILD_LIBUMF_POOL_DISJOINT
   AND UMF_BUILD_CUDA_PROVIDER
   AND UMF_CUDA_ENABLED)
    set(EXAMPLE_NAME umf_example_cuda_shared_memory)

    add_umf_executable(
        NAME ${EXAMPLE_NAME}
        SRCS cuda_shared_memory/cuda_shared_memory.c
        LIBS disjoint_pool cuda umf)

    target_include_directories(
        ${EXAMPLE_NAME}
        PRIVATE ${CUDA_INCLUDE_DIRS} ${UMF_CMAKE_SOURCE_DIR}/src/utils
                ${UMF_CMAKE_SOURCE_DIR}/include
                ${UMF_CMAKE_SOURCE_DIR}/examples/common)

    target_link_directories(${EXAMPLE_NAME} PRIVATE ${LIBHWLOC_LIBRARY_DIRS}
                            ${CUDA_LIBRARY_DIRS})

    add_test(
        NAME ${EXAMPLE_NAME}
        COMMAND ${EXAMPLE_NAME}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

    set_tests_properties(${EXAMPLE_NAME} PROPERTIES LABELS "example")

    if(WINDOWS)
        # append PATH to DLLs
        set_property(TEST ${EXAMPLE_NAME} PROPERTY ENVIRONMENT_MODIFICATION
                                                   "${DLL_PATH_LIST}")
    endif()
else()
    message(
        STATUS
            "GPU CUDA shared memory example requires UMF_BUILD_GPU_EXAMPLES, UMF_BUILD_CUDA_PROVIDER, UMF_BUILD_LIBUMF_POOL_DISJOINT to be turned ON and installed CUDA libraries - skipping"
    )
endif()

# TODO: it looks like there is some problem with IPC implementation in Level
# Zero on windows
if(UMF_BUILD_GPU_EXAMPLES
   AND UMF_BUILD_LIBUMF_POOL_DISJOINT
   AND UMF_BUILD_LEVEL_ZERO_PROVIDER
   AND LINUX)
    set(EXAMPLE_NAME umf_example_ipc_level_zero)

    add_umf_executable(
        NAME ${EXAMPLE_NAME}
        SRCS ipc_level_zero/ipc_level_zero.c
        LIBS disjoint_pool ze_loader umf)

    target_include_directories(
        ${EXAMPLE_NAME}
        PRIVATE ${LEVEL_ZERO_INCLUDE_DIRS} ${UMF_CMAKE_SOURCE_DIR}/src/utils
                ${UMF_CMAKE_SOURCE_DIR}/include
                ${UMF_CMAKE_SOURCE_DIR}/examples/common)

    target_link_directories(${EXAMPLE_NAME} PRIVATE ${LIBHWLOC_LIBRARY_DIRS})

    add_test(
        NAME ${EXAMPLE_NAME}
        COMMAND ${EXAMPLE_NAME}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

    set_tests_properties(${EXAMPLE_NAME} PROPERTIES LABELS "example")

    if(WINDOWS)
        # append PATH to DLLs
        set_property(TEST ${EXAMPLE_NAME} PROPERTY ENVIRONMENT_MODIFICATION
                                                   "${DLL_PATH_LIST}")
    endif()
else()
    message(
        STATUS
            "IPC Level 0 example requires UMF_BUILD_GPU_EXAMPLES, UMF_BUILD_LEVEL_ZERO_PROVIDER and UMF_BUILD_LIBUMF_POOL_DISJOINT to be turned ON - skipping"
    )
endif()

function(build_umf_ipc_example name)
    set(BASE_NAME ${name})
    set(EXAMPLE_NAME umf_example_${BASE_NAME})

    foreach(loop_var IN ITEMS "producer" "consumer")
        set(EX_NAME ${EXAMPLE_NAME}_${loop_var})
        add_umf_executable(
            NAME ${EX_NAME}
            SRCS ipc_ipcapi/${BASE_NAME}_${loop_var}.c
            LIBS umf)

        target_include_directories(
            ${EX_NAME} PRIVATE ${UMF_CMAKE_SOURCE_DIR}/src/utils
                               ${UMF_CMAKE_SOURCE_DIR}/include)

        target_link_directories(${EX_NAME} PRIVATE ${LIBHWLOC_LIBRARY_DIRS}
                                ${TBB_LIBRARY_DIRS})
    endforeach(loop_var)
endfunction()

function(add_umf_ipc_example script)
    set(EXAMPLE_NAME umf_example_${script})

    file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/ipc_ipcapi/${script}.sh
         DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

    add_test(
        NAME ${EXAMPLE_NAME}
        COMMAND ${script}.sh
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

    set_tests_properties(${EXAMPLE_NAME} PROPERTIES LABELS "example")
    if(NOT UMF_TESTS_FAIL_ON_SKIP)
        set_tests_properties(${EXAMPLE_NAME} PROPERTIES SKIP_RETURN_CODE 125)
    endif()
endfunction()

if(LINUX AND UMF_POOL_SCALABLE_ENABLED)
    build_umf_ipc_example(ipc_ipcapi)
    add_umf_ipc_example(ipc_ipcapi_anon_fd)
    add_umf_ipc_example(ipc_ipcapi_shm)
else()
    message(
        STATUS
            "IPC examples with UMF pool API are supported on Linux only - skipping"
    )
endif()

if(LINUX)
    set(UMF_TEST_SKIP_RETURN_CODE 125)

    set(EXAMPLE_NAME umf_example_memspace_numa)

    add_umf_executable(
        NAME ${EXAMPLE_NAME}
        SRCS memspace_numa/memspace_numa.c
        LIBS umf ${LIBHWLOC_LIBRARIES} numa)

    target_include_directories(
        ${EXAMPLE_NAME}
        PRIVATE ${UMF_CMAKE_SOURCE_DIR}/src/utils
                ${UMF_CMAKE_SOURCE_DIR}/include
                ${UMF_CMAKE_SOURCE_DIR}/examples/common)

    target_link_directories(${EXAMPLE_NAME} PRIVATE ${LIBHWLOC_LIBRARY_DIRS})

    add_test(
        NAME ${EXAMPLE_NAME}
        COMMAND ${EXAMPLE_NAME}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

    set_tests_properties(${EXAMPLE_NAME} PROPERTIES
                         SKIP_RETURN_CODE ${UMF_TEST_SKIP_RETURN_CODE})

    set(EXAMPLE_NAME umf_example_memspace_hmat)

    add_umf_executable(
        NAME ${EXAMPLE_NAME}
        SRCS memspace_hmat/memspace_hmat.c
        LIBS umf ${LIBHWLOC_LIBRARIES} numa)

    target_include_directories(
        ${EXAMPLE_NAME}
        PRIVATE ${UMF_CMAKE_SOURCE_DIR}/src/utils
                ${UMF_CMAKE_SOURCE_DIR}/include
                ${UMF_CMAKE_SOURCE_DIR}/examples/common)

    target_link_directories(${EXAMPLE_NAME} PRIVATE ${LIBHWLOC_LIBRARY_DIRS})

    add_test(
        NAME ${EXAMPLE_NAME}
        COMMAND ${EXAMPLE_NAME}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

    set_tests_properties(${EXAMPLE_NAME} PROPERTIES
                         SKIP_RETURN_CODE ${UMF_TEST_SKIP_RETURN_CODE})

    if(UMF_POOL_SCALABLE_ENABLED)
        set(EXAMPLE_NAME umf_example_custom_file_provider)

        add_umf_executable(
            NAME ${EXAMPLE_NAME}
            SRCS custom_file_provider/custom_file_provider.c
            LIBS umf ${LIBHWLOC_LIBRARIES})

        target_include_directories(
            ${EXAMPLE_NAME} PRIVATE ${UMF_CMAKE_SOURCE_DIR}/src/utils
                                    ${UMF_CMAKE_SOURCE_DIR}/include)

        target_link_directories(${EXAMPLE_NAME} PRIVATE
                                ${LIBHWLOC_LIBRARY_DIRS} ${TBB_LIBRARY_DIRS})

        add_test(
            NAME ${EXAMPLE_NAME}
            COMMAND ${EXAMPLE_NAME}
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
    endif()

    if(UMF_POOL_JEMALLOC_ENABLED)
        set(EXAMPLE_NAME umf_example_dram_and_fsdax)

        add_umf_executable(
            NAME ${EXAMPLE_NAME}
            SRCS dram_and_fsdax/dram_and_fsdax.c
            LIBS umf jemalloc_pool)

        target_link_directories(${EXAMPLE_NAME} PRIVATE
                                ${LIBHWLOC_LIBRARY_DIRS})

        add_test(
            NAME ${EXAMPLE_NAME}
            COMMAND ${EXAMPLE_NAME}
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
    endif()
else()
    message(
        STATUS "Memspace examples API are supported on Linux only - skipping")
    message(
        STATUS "File provider example is supported on Linux only - skipping")
endif()
