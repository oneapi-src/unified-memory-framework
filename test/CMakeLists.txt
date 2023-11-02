# Copyright (C) 2022-2023 Intel Corporation
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
FetchContent_MakeAvailable(googletest)
enable_testing()

set(UMF_TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR})

function(add_umf_test name)
    set(TEST_TARGET_NAME umf_test-${name})
    add_umf_executable(${TEST_TARGET_NAME}
        ${ARGN})
    target_link_libraries(${TEST_TARGET_NAME}
        PRIVATE
        ${PROJECT_NAME}::unified_memory_framework
        GTest::gtest_main)
    target_include_directories(${TEST_TARGET_NAME} PRIVATE
        ${UMF_TEST_DIR}/common)
    add_test(NAME  umf-${name}
        COMMAND ${TEST_TARGET_NAME}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
    set_tests_properties(umf-${name} PROPERTIES LABELS "umf")
endfunction()

add_umf_test(base base.cpp)
add_umf_test(memoryPool memoryPoolAPI.cpp common/test_helpers.c)
add_umf_test(memoryProvider memoryProviderAPI.cpp common/test_helpers.c)
