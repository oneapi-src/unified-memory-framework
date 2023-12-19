# Copyright (C) 2023 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#
# helpers.cmake -- helper functions for top-level CMakeLists.txt
#

# Sets ${ret} to version of program specified by ${name} in major.minor format
function(get_program_version_major_minor name ret)
    execute_process(COMMAND ${name} --version
        OUTPUT_VARIABLE cmd_ret
        ERROR_QUIET)
    STRING(REGEX MATCH "([0-9]+)\.([0-9]+)" VERSION "${cmd_ret}")
    SET(${ret} ${VERSION} PARENT_SCOPE)
endfunction()

function(add_umf_target_compile_options name)
    if(NOT MSVC)
        target_compile_options(${name} PRIVATE
            -fPIC
            -Wall
            -Wpedantic
            -Wempty-body
            -Wunused-parameter
            $<$<CXX_COMPILER_ID:GNU>:-fdiagnostics-color=always>
            $<$<CXX_COMPILER_ID:Clang,AppleClang>:-fcolor-diagnostics>
        )
        if (CMAKE_BUILD_TYPE STREQUAL "Release")
            target_compile_definitions(${name} PRIVATE -D_FORTIFY_SOURCE=2)
        endif()
        if(UMF_DEVELOPER_MODE)
            target_compile_options(${name} PRIVATE
                -Werror
                -fno-omit-frame-pointer
                -fstack-protector-strong
            )
        endif()
    elseif(MSVC)
        target_compile_options(${name} PRIVATE
            $<$<CXX_COMPILER_ID:MSVC>:/MP>  # clang-cl.exe does not support /MP
            /W3
            /MD$<$<CONFIG:Debug>:d>
            /GS
        )

        if(UMF_DEVELOPER_MODE)
            target_compile_options(${name} PRIVATE /WX /GS)
        endif()
    endif()
endfunction()

function(add_umf_target_link_options name)
    if(NOT MSVC)
        if (NOT APPLE)
            target_link_options(${name} PRIVATE "LINKER:-z,relro,-z,now")
        endif()
    elseif(MSVC)
        target_link_options(${name} PRIVATE
            /DYNAMICBASE
            /HIGHENTROPYVA
            /NXCOMPAT
        )
    endif()
endfunction()

function(add_umf_target_exec_options name)
    if(MSVC)
        target_link_options(${name} PRIVATE
            /ALLOWISOLATION
        )
    endif()
endfunction()

function(add_umf_executable name)
    add_executable(${name} ${ARGN})
    add_umf_target_compile_options(${name})
    add_umf_target_exec_options(${name})
    add_umf_target_link_options(${name})
endfunction()

function(add_umf_library name)
    add_library(${name} ${ARGN})
    target_include_directories(${name} PRIVATE
        ${UMF_CMAKE_SOURCE_DIR}/include
        ${UMF_CMAKE_SOURCE_DIR}/src/common)
    add_umf_target_compile_options(${name})
    add_umf_target_link_options(${name})
endfunction()
