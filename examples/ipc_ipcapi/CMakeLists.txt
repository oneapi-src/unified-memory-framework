# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14.0 FATAL_ERROR)
project(umf_example_ipc_ipcapi LANGUAGES C)
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

pkg_check_modules(TBB tbb)
if(NOT TBB_FOUND)
    find_package(TBB REQUIRED tbb)
endif()

# build the example
function(build_umf_ipc_example name)
    set(BASE_NAME ${name})
    set(EXAMPLE_NAME umf_example_${BASE_NAME})

    foreach(loop_var IN ITEMS "producer" "consumer")
        set(EX_NAME ${EXAMPLE_NAME}_${loop_var})
        add_executable(${EX_NAME} ${BASE_NAME}_${loop_var}.c)
        target_include_directories(${EX_NAME} PRIVATE ${LIBUMF_INCLUDE_DIRS})
        target_link_directories(${EX_NAME} PRIVATE ${LIBHWLOC_LIBRARY_DIRS})
        target_link_libraries(${EX_NAME} PRIVATE ${LIBUMF_LIBRARIES} hwloc)
    endforeach(loop_var)
endfunction()

# an optional part - adds a test of this example
function(add_test_for_umf_ipc_example script)
    set(EXAMPLE_NAME umf_example_${script})

    file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/${script}.sh
         DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

    add_test(
        NAME ${EXAMPLE_NAME}
        COMMAND ${script}.sh
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

    if(LINUX)
        set_property(
            TEST ${EXAMPLE_NAME}
            PROPERTY
                ENVIRONMENT_MODIFICATION
                "LD_LIBRARY_PATH=path_list_append:${LIBUMF_LIBRARY_DIRS};LD_LIBRARY_PATH=path_list_append:${LIBHWLOC_LIBRARY_DIRS}"
        )
    endif()

    set_tests_properties(${EXAMPLE_NAME} PROPERTIES LABELS "example-standalone")
    if(NOT UMF_TESTS_FAIL_ON_SKIP)
        set_tests_properties(${EXAMPLE_NAME} PROPERTIES SKIP_RETURN_CODE 125)
    endif()
endfunction()

# build the example
build_umf_ipc_example(ipc_ipcapi)

# an optional part - adds a test of this example
add_test_for_umf_ipc_example(ipc_ipcapi_anon_fd)
add_test_for_umf_ipc_example(ipc_ipcapi_shm)
