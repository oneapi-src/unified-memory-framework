# Copyright (C) 2023-2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#
# helpers.cmake -- helper functions for top-level CMakeLists.txt
#

# CMake modules that check whether the C/C++ compiler supports a given flag
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

# This function establishes version variables based on the git describe output.
# If there's no git available in the system, the version will be set to "0.0.0".
# If git reports only a hash, the version will be set to "0.0.0.git.<hash>".
# Otherwise we'll use 3-component version: major.minor.patch, just for CMake's
# sake. A few extra variables will be set for Win dll metadata.
#
# Important note: CMake does not support rc or git information. According to
# semver rules, 1.5.1-rc1 should be less than 1.5.1, but it seems hard to
# achieve such comparison in CMake. So, for CMake's sake we only set 3-component
# version in variable "UMF_CMAKE_VERSION", ignoring the rc and git information.
# It's only used to set SOVERSION and creating "umf-config.cmake" file.
#
# For Windows versioning in dll metadata, we use 4-component version plus a few
# additional variables. REVISION has to be an integer and is calculated as:
# REVISION = rc_no * 1000 + git_commit_no (commits count after the last release)
#
# For all other usages (beside CMake and Win dll), we use semver aligned version
# "UMF_VERSION", which is in line with our tags (e.g. "1.5.0-rc2").
#
# Example parsing of git output:
# cmake-format: off
# +-----------------------+-------+-------+-------+----------+--------+---------+------------+
# |               \ CMake:| Major | Minor | Patch |          |        |         |            |
# +-----------------------+-------+-------+-------+----------+--------+---------+------------+
# | git describe  \ Win32:| MAJOR | MINOR | BUILD | REVISION | BUGFIX | PRIVATE | PRERELEASE |
# +-----------------------+-------+-------+-------+----------+--------+---------+------------+
# | 1.5.0-rc2-0-gb8f7a32  | 1     | 5     | 0     | 2000     |        |         |   true     |
# | 1.5.0-rc2             | 1     | 5     | 0     | 2000     |        |         |   true     |
# | 1.5.0-rc3-6-gb8f7a32  | 1     | 5     | 0     | 3006     |        |   true  |   true     |
# | 1.5.0-0-gb8f7a32      | 1     | 5     | 0     | 0        |        |         |            |
# | 1.5.0                 | 1     | 5     | 0     | 0        |        |         |            |
# | 1.5.0-6-123345678     | 1     | 5     | 0     | 6        |        |   true  |            |
# | 1.5.2-rc1-0-gb8f7a32  | 1     | 5     | 2     | 1000     |   true |         |   true     |
# | 1.5.2-rc4-6-gb8f7a32  | 1     | 5     | 2     | 4006     |   true |   true  |   true     |
# | 1.5.2-0-gb8f7a32      | 1     | 5     | 2     | 0        |   true |         |            |
# | 1.5.2-6-gb8f7a32      | 1     | 5     | 2     | 6        |   true |   true  |            |
# | gb8f7a32              | 0     | 0     | 0     | 0        |        |   true  |            |
# | ? (no git)            | 0     | 0     | 0     | 0        |        |   true  |            |
# +-----------------------+-------+-------+-------+----------+--------+---------+------------+
# cmake-format: on
function(set_version_variables)
    # default values
    set(UMF_VERSION_PRERELEASE
        0
        PARENT_SCOPE)
    set(UMF_VERSION_PRIVATE
        1
        PARENT_SCOPE)
    set(UMF_VERSION_BUGFIX
        0
        PARENT_SCOPE)
    set(UMF_VERSION_REVISION
        0
        PARENT_SCOPE)
    set(UMF_CMAKE_VERSION
        "0.0.0"
        PARENT_SCOPE)
    set(UMF_VERSION
        "0.0.0"
        PARENT_SCOPE)

    execute_process(
        COMMAND git describe --always
        OUTPUT_VARIABLE GIT_VERSION
        WORKING_DIRECTORY ${UMF_CMAKE_SOURCE_DIR}
        OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)

    if(NOT GIT_VERSION)
        # no git or it reported no version. Use default ver: "0.0.0"
        return()
    endif()

    # v1.5.0 - we're exactly on a tag -> UMF ver: "1.5.0"
    string(REGEX MATCHALL "\^v([0-9]+\.[0-9]+\.[0-9]+)\$" MATCHES
                 ${GIT_VERSION})
    if(MATCHES)
        set(UMF_VERSION
            "${CMAKE_MATCH_1}"
            PARENT_SCOPE)
        set(UMF_CMAKE_VERSION
            "${CMAKE_MATCH_1}"
            PARENT_SCOPE)
        set(UMF_VERSION_PRIVATE
            0
            PARENT_SCOPE)
        return()
    endif()

    # v1.5.0-rc1 - we're on a RC tag -> UMF ver: "1.5.0-rc1"
    string(REGEX MATCHALL "\^v([0-9]+\.[0-9]+\.[0-9]+)-rc([0-9]+)\$" MATCHES
                 ${GIT_VERSION})
    if(MATCHES)
        set(UMF_VERSION
            "${CMAKE_MATCH_1}-rc${CMAKE_MATCH_2}"
            PARENT_SCOPE)
        set(UMF_CMAKE_VERSION
            "${CMAKE_MATCH_1}"
            PARENT_SCOPE)
        math(EXPR revision "${CMAKE_MATCH_2} * 1000")
        set(UMF_VERSION_REVISION
            ${revision}
            PARENT_SCOPE)
        set(UMF_VERSION_PRERELEASE
            1
            PARENT_SCOPE)
        set(UMF_VERSION_PRIVATE
            0
            PARENT_SCOPE)
        return()
    endif()

    # v1.5.0-dev - we're on a development tag -> UMF ver: "1.5.0-dev"
    string(REGEX MATCHALL "\^v([0-9]+\.[0-9]+\.[0-9]+)-dev\$" MATCHES
                 ${GIT_VERSION})
    if(MATCHES)
        set(UMF_VERSION
            "${CMAKE_MATCH_1}-dev"
            PARENT_SCOPE)
        set(UMF_CMAKE_VERSION
            "${CMAKE_MATCH_1}"
            PARENT_SCOPE)
        set(UMF_VERSION_PRIVATE
            0
            PARENT_SCOPE)
        return()
    endif()

    # v1.5.0-rc1-19-gb8f7a32 -> UMF ver: "1.5.0-rc1.git19.gb8f7a32"
    string(REGEX MATCHALL "v([0-9.]*)-rc([0-9]*)-([0-9]*)-([0-9a-g]*)" MATCHES
                 ${GIT_VERSION})
    if(MATCHES)
        set(UMF_VERSION
            "${CMAKE_MATCH_1}-rc${CMAKE_MATCH_2}.git${CMAKE_MATCH_3}.${CMAKE_MATCH_4}"
            PARENT_SCOPE)
        set(UMF_CMAKE_VERSION
            "${CMAKE_MATCH_1}"
            PARENT_SCOPE)
        math(EXPR revision "${CMAKE_MATCH_2} * 1000 + ${CMAKE_MATCH_3}")
        set(UMF_VERSION_REVISION
            ${revision}
            PARENT_SCOPE)
        set(UMF_VERSION_PRERELEASE
            1
            PARENT_SCOPE)
        return()
    endif()

    # v1.5.0-dev-19-gb8f7a32 -> UMF ver: "1.5.0-dev.git19.gb8f7a32"
    string(REGEX MATCHALL "v([0-9.]*)-dev-([0-9]*)-([0-9a-g]*)" MATCHES
                 ${GIT_VERSION})
    if(MATCHES)
        set(UMF_VERSION
            "${CMAKE_MATCH_1}-dev.git${CMAKE_MATCH_2}.${CMAKE_MATCH_3}"
            PARENT_SCOPE)
        set(UMF_CMAKE_VERSION
            "${CMAKE_MATCH_1}"
            PARENT_SCOPE)
        return()
    endif()

    # v1.5.0-19-gb8f7a32 -> UMF ver: "1.5.0-git19.gb8f7a32"
    string(REGEX MATCHALL "v([0-9.]*)-([0-9]*)-([0-9a-g]*)" MATCHES
                 ${GIT_VERSION})
    if(MATCHES)
        set(UMF_VERSION
            "${CMAKE_MATCH_1}-git${CMAKE_MATCH_2}.${CMAKE_MATCH_3}"
            PARENT_SCOPE)
        set(UMF_CMAKE_VERSION
            "${CMAKE_MATCH_1}"
            PARENT_SCOPE)
        set(UMF_VERSION_REVISION
            ${CMAKE_MATCH_2}
            PARENT_SCOPE)
        return()
    endif()

    # no full version is available (e.g. only a hash commit) or a pattern was
    # not recognized -> UMF ver: "0.0.0.git.<hash>"
    set(UMF_VERSION
        "0.0.0.git.${GIT_VERSION}"
        PARENT_SCOPE)
endfunction()

# Sets ${ret} to version of program specified by ${name} in major.minor format
function(get_program_version_major_minor name ret)
    execute_process(
        COMMAND ${name} --version
        OUTPUT_VARIABLE cmd_ret
        ERROR_QUIET)
    string(REGEX MATCH "([0-9]+)\.([0-9]+)" VERSION "${cmd_ret}")
    set(${ret}
        ${VERSION}
        PARENT_SCOPE)
endfunction()

# Checks compiler for given ${flag}, stores the output in C_HAS_${flag} and
# CXX_HAS_${flag} (if compiler supports C++)
function(check_compilers_flag flag)
    check_c_compiler_flag("${flag}" "C_HAS_${flag}")
    if(CMAKE_CXX_COMPILE_FEATURES)
        check_cxx_compiler_flag("${flag}" "CXX_HAS_${flag}")
    endif()
endfunction()

function(check_add_target_compile_options target)
    foreach(option ${ARGN})
        check_compilers_flag(${option})
        if(C_HAS_${option} AND CXX_HAS_${option})
            target_compile_options(${target} PRIVATE ${option})
        endif()
    endforeach()
endfunction()

function(add_umf_target_compile_options name)
    check_add_target_compile_options(${name} "-Wno-covered-switch-default")

    if(NOT MSVC)
        target_compile_options(
            ${name}
            PRIVATE -fPIC
                    -Wall
                    -Wextra
                    -Wpedantic
                    -Wempty-body
                    -Wunused-parameter
                    -Wformat
                    -Wformat-security
                    -Wcast-qual
                    -Wunused-result
                    $<$<CXX_COMPILER_ID:GNU>:-fdiagnostics-color=auto>)
        if(CMAKE_BUILD_TYPE STREQUAL "Release")
            target_compile_definitions(${name} PRIVATE -D_FORTIFY_SOURCE=2)
        endif()
        if(UMF_DEVELOPER_MODE)
            target_compile_options(${name} PRIVATE -fno-omit-frame-pointer
                                                   -fstack-protector-strong)
        endif()
        if(UMF_USE_COVERAGE)
            if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
                message(
                    FATAL_ERROR
                        "To use the --coverage flag, the build type must be Debug"
                )
            endif()
            target_compile_options(${name} PRIVATE --coverage)
            if(${CMAKE_C_COMPILER} MATCHES "gcc")
                # Fix for the following error: geninfo: ERROR: Unexpected
                # negative count '-1' for provider_os_memory.c:1037. Perhaps you
                # need to compile with '-fprofile-update=atomic
                target_compile_options(${name} PRIVATE -fprofile-update=atomic
                                                       -g -O0)
            endif()
        endif()
    elseif(MSVC)
        target_compile_options(
            ${name}
            PRIVATE /MD$<$<CONFIG:Debug>:d>
                    $<$<CONFIG:Release>:/sdl>
                    $<$<CXX_COMPILER_ID:MSVC>:/analyze>
                    /DYNAMICBASE
                    /W4
                    /Gy
                    /GS
                    # disable warning 6326: Potential comparison of a constant
                    # with another constant
                    /wd6326
                    # disable 4200 warning: nonstandard extension used:
                    # zero-sized array in struct/union
                    /wd4200)
        if(${CMAKE_C_COMPILER_ID} MATCHES "MSVC")
            target_compile_options(
                ${name}
                PRIVATE # below flags are not recognized by Clang
                        /MP $<$<CONFIG:Release>:/LTCG>
                        $<$<CONFIG:Release>:/NXCOMPAT>)
        endif()
    endif()
endfunction()

function(add_umf_target_link_options name)
    if(NOT MSVC)
        if(NOT APPLE)
            target_link_options(${name} PRIVATE "LINKER:-z,relro,-z,now")
            if(UMF_USE_COVERAGE)
                if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
                    message(
                        FATAL_ERROR
                            "To use the --coverage flag, the build type must be Debug"
                    )
                endif()
                target_link_options(${name} PRIVATE --coverage)
            endif()
        endif()
    elseif(MSVC)
        target_link_options(
            ${name}
            PRIVATE
            LINKER:/DYNAMICBASE
            LINKER:/HIGHENTROPYVA
            $<$<C_COMPILER_ID:MSVC>:/DEPENDENTLOADFLAG:0x2000>
            $<$<CXX_COMPILER_ID:MSVC>:/DEPENDENTLOADFLAG:0x2000>
            LINKER:/NXCOMPAT)
    endif()
endfunction()

function(add_umf_target_exec_options name)
    if(MSVC)
        target_link_options(${name} PRIVATE LINKER:/ALLOWISOLATION)
    endif()
endfunction()

function(add_umf_executable)
    # Parameters:
    #
    # * NAME - a name of the executable
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

    add_executable(${ARG_NAME} ${ARG_SRCS})
    target_link_libraries(${ARG_NAME} PRIVATE ${ARG_LIBS})
    add_umf_target_compile_options(${ARG_NAME})
    add_umf_target_exec_options(${ARG_NAME})
    add_umf_target_link_options(${ARG_NAME})
endfunction()

function(add_umf_library)
    # Parameters:
    #
    # * NAME - a name of the library
    # * TYPE - type of the library (shared or static) if shared library,
    #   LINUX_MAP_FILE and WINDOWS_DEF_FILE must also be specified
    # * SRCS - source files
    # * LIBS - libraries to be linked with
    # * LINUX_MAP_FILE - path to linux linker map (.map) file
    # * WINDOWS_DEF_FILE - path to windows module-definition (DEF) file

    set(oneValueArgs NAME TYPE LINUX_MAP_FILE WINDOWS_DEF_FILE)
    set(multiValueArgs SRCS LIBS)
    cmake_parse_arguments(
        ARG
        ""
        "${oneValueArgs}"
        "${multiValueArgs}"
        ${ARGN})

    add_library(${ARG_NAME} ${ARG_TYPE} ${ARG_SRCS})

    string(TOUPPER "${ARG_TYPE}" ARG_TYPE)
    if(ARG_TYPE STREQUAL "SHARED")
        if(NOT ARG_LINUX_MAP_FILE OR NOT ARG_WINDOWS_DEF_FILE)
            message(FATAL_ERROR "LINUX_MAP_FILE or WINDOWS_DEF_FILE "
                                "not specified")
        endif()

        if(WINDOWS)
            target_link_options(${ARG_NAME} PRIVATE
                                LINKER:/DEF:${ARG_WINDOWS_DEF_FILE})
        elseif(LINUX)
            target_link_options(${ARG_NAME} PRIVATE
                                "-Wl,--version-script=${ARG_LINUX_MAP_FILE}")
        endif()
    endif()

    target_link_libraries(${ARG_NAME} PRIVATE ${ARG_LIBS})

    target_include_directories(
        ${ARG_NAME}
        PRIVATE ${UMF_CMAKE_SOURCE_DIR}/include
                ${UMF_CMAKE_SOURCE_DIR}/src/utils
                ${UMF_CMAKE_SOURCE_DIR}/src/base_alloc)
    add_umf_target_compile_options(${ARG_NAME})
    add_umf_target_link_options(${ARG_NAME})
endfunction()

# Add sanitizer ${flag}, if it is supported, for both C and C++ compiler
macro(add_sanitizer_flag flag)
    set(SANITIZER_FLAG "-fsanitize=${flag}")
    if(NOT MSVC)
        # Not available on MSVC.
        set(SANITIZER_ARGS "-fno-sanitize-recover=all")
    endif()

    # Save current 'SAVED_CMAKE_REQUIRED_FLAGS' state and temporarily extend it
    # with '-fsanitize=${flag}'. It is required by CMake to check the compiler
    # for availability of provided sanitizer ${flag}.
    set(SAVED_CMAKE_REQUIRED_FLAGS ${CMAKE_REQUIRED_FLAGS})
    set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} ${SANITIZER_FLAG}")

    if(${flag} STREQUAL "address")
        set(check_name "HAS_ASAN")
    elseif(${flag} STREQUAL "undefined")
        set(check_name "HAS_UBSAN")
    elseif(${flag} STREQUAL "thread")
        set(check_name "HAS_TSAN")
    elseif(${flag} STREQUAL "memory")
        set(check_name "HAS_MSAN")
    endif()

    # Check C and CXX compilers for a given sanitizer flag.
    check_c_compiler_flag("${SANITIZER_FLAG}" "C_${check_name}")
    if(NOT C_${check_name})
        message(FATAL_ERROR "sanitizer '${flag}' is not supported "
                            "by the C compiler)")
    endif()
    if(CMAKE_CXX_COMPILE_FEATURES)
        check_cxx_compiler_flag("${SANITIZER_FLAG}" "CXX_${check_name}")
        if(NOT CXX_${check_name})
            message(FATAL_ERROR "sanitizer '${flag}' is not supported by the "
                                "CXX compiler)")
        endif()
    endif()

    add_compile_options("${SANITIZER_FLAG}")

    # Check C and CXX compilers for sanitizer arguments.
    if(SANITIZER_ARGS)
        check_c_compiler_flag("${SANITIZER_ARGS}" "C_HAS_SAN_ARGS")
        if(NOT C_HAS_SAN_ARGS)
            message(FATAL_ERROR "sanitizer argument '${SANITIZER_ARGS}' is "
                                "not supported by the C compiler)")
        endif()
        if(CMAKE_CXX_COMPILE_FEATURES)
            check_cxx_compiler_flag("${SANITIZER_ARGS}" "CXX_HAS_SAN_ARGS")
            if(NOT CXX_HAS_SAN_ARGS)
                message(FATAL_ERROR "sanitizer argument '${SANITIZER_ARGS}' "
                                    "is not supported by the CXX compiler)")
            endif()
        endif()

        add_compile_options("${SANITIZER_ARGS}")
    endif()

    # Clang/gcc needs the flag added to the linker. The Microsoft LINK linker
    # doesn't recognize sanitizer flags and will give a LNK4044 warning.
    if(NOT MSVC)
        add_link_options("${SANITIZER_FLAG}")
    endif()

    set(CMAKE_REQUIRED_FLAGS ${SAVED_CMAKE_REQUIRED_FLAGS})
endmacro()
