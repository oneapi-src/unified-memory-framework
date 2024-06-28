# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

message(STATUS "Fuzzing tests enabled.")

function(add_fuzz_test name label)
    add_test(
        NAME "fuzz-${name}"
        COMMAND fuzztest ${ARGN} -verbosity=1
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
    set_tests_properties("fuzz-${name}" PROPERTIES LABELS ${label})
endfunction()

set(TEST_TARGET_NAME fuzztest)
add_umf_executable(
    NAME ${TEST_TARGET_NAME}
    SRCS umfFuzz.cpp
    LIBS umf)
target_link_libraries(${TEST_TARGET_NAME} PRIVATE umf -fsanitize=fuzzer)
target_compile_options(${TEST_TARGET_NAME} PRIVATE -g -fsanitize=fuzzer)
target_include_directories(${TEST_TARGET_NAME}
                           PRIVATE ${UMF_CMAKE_SOURCE_DIR}/include)
target_link_directories(${TEST_TARGET_NAME} PRIVATE ${LIBHWLOC_LIBRARY_DIRS})

add_fuzz_test(basic_long fuzz-long -max_total_time=600)
