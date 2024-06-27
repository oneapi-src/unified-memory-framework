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
    LIBS umf hwloc)

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
    set(EXAMPLE_NAME umf_example_gpu_shared_memory)

    add_umf_executable(
        NAME ${EXAMPLE_NAME}
        SRCS basic/gpu_shared_memory.c
        LIBS disjoint_pool ze_loader umf)

    target_include_directories(
        ${EXAMPLE_NAME} PRIVATE ${UMF_CMAKE_SOURCE_DIR}/src/utils
                                ${UMF_CMAKE_SOURCE_DIR}/include)

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
            "GPU shared memory example requires UMF_BUILD_GPU_EXAMPLES, "
            "UMF_BUILD_LEVEL_ZERO_PROVIDER and UMF_BUILD_LIBUMF_POOL_DISJOINT "
            "to be turned ON - skipping")
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
        SRCS basic/ipc_level_zero.c
        LIBS disjoint_pool ze_loader umf)

    target_include_directories(
        ${EXAMPLE_NAME}
        PRIVATE ${LEVEL_ZERO_INCLUDE_DIRS} ${UMF_CMAKE_SOURCE_DIR}/src/utils
                ${UMF_CMAKE_SOURCE_DIR}/include)

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
            SRCS basic/${BASE_NAME}_${loop_var}.c
            LIBS umf)

        target_include_directories(
            ${EX_NAME} PRIVATE ${UMF_CMAKE_SOURCE_DIR}/src/utils
                               ${UMF_CMAKE_SOURCE_DIR}/include)

        target_link_directories(${EX_NAME} PRIVATE ${LIBHWLOC_LIBRARY_DIRS})
    endforeach(loop_var)
endfunction()

function(add_umf_ipc_example script)
    set(EXAMPLE_NAME umf_example_${script})

    file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/basic/${script}.sh
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

if(LINUX)
    build_umf_ipc_example(ipc_ipcapi)
    add_umf_ipc_example(ipc_ipcapi_anon_fd)
    add_umf_ipc_example(ipc_ipcapi_shm)
else()
    message(
        STATUS
            "IPC examples with UMF pool API are supported on Linux only - skipping"
    )
endif()
