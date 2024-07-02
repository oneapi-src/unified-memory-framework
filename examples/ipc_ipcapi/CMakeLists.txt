# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

function(build_umf_ipc_example name)
    set(BASE_NAME ${name})
    set(EXAMPLE_NAME umf_example_${BASE_NAME})

    foreach(loop_var IN ITEMS "producer" "consumer")
        set(EX_NAME ${EXAMPLE_NAME}_${loop_var})
        add_umf_executable(
            NAME ${EX_NAME}
            SRCS ${BASE_NAME}_${loop_var}.c
            LIBS umf)

        target_include_directories(
            ${EX_NAME} PRIVATE ${UMF_CMAKE_SOURCE_DIR}/src/utils
                               ${UMF_CMAKE_SOURCE_DIR}/include)

        target_link_directories(${EX_NAME} PRIVATE ${LIBHWLOC_LIBRARY_DIRS})
    endforeach(loop_var)
endfunction()

function(add_umf_ipc_example script)
    set(EXAMPLE_NAME umf_example_${script})

    file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/${script}.sh
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

build_umf_ipc_example(ipc_ipcapi)
add_umf_ipc_example(ipc_ipcapi_anon_fd)
add_umf_ipc_example(ipc_ipcapi_shm)
