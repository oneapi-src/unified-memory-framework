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
            #$<$<CXX_COMPILER_ID:GNU>:-fdiagnostics-color=always>
            #$<$<CXX_COMPILER_ID:Clang,AppleClang>:-fcolor-diagnostics>
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
            set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,relro -Wl,-z,now")
        endif()
    elseif(MSVC)
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT")
    endif()
endfunction()

function(add_umf_target_exec_options name)
    if(MSVC)
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /ALLOWISOLATION")
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

# A wrapper around FetchContent_Declare that supports git checkout
function(FetchContentCheckout_Declare SRC_DIR GIT_REPOSITORY GIT_BRANCH GIT_HASH)
    set(external-content-dir ${SRC_DIR})
    message(STATUS "Fetching all content from ${GIT_REPOSITORY}/${GIT_BRANCH} commit hash ${GIT_HASH}")
    if(NOT EXISTS ${external-content-dir}/.git)
        execute_process(COMMAND git init -b ${GIT_BRANCH}
            WORKING_DIRECTORY ${external-content-dir})
        execute_process(COMMAND git remote add origin ${GIT_REPOSITORY}
            WORKING_DIRECTORY ${external-content-dir})
    endif()
    execute_process(COMMAND git fetch origin ${GIT_BRANCH}
        WORKING_DIRECTORY ${external-content-dir})
    execute_process(COMMAND git config advice.detachedHead false
        WORKING_DIRECTORY ${external-content-dir})
    execute_process(COMMAND git reset --hard ${GIT_HASH}
        WORKING_DIRECTORY ${external-content-dir})
        
    include(FetchContent)
    FetchContent_Declare(
        ${name}
        GIT_REPOSITORY ${GIT_REPOSITORY}
        GIT_TAG        ${GIT_HASH}
        SOURCE_DIR     ${external-content-dir}/)
endfunction()
