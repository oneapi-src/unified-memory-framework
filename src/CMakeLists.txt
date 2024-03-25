# Copyright (C) 2023-2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

include(${UMF_CMAKE_SOURCE_DIR}/cmake/helpers.cmake)

if(UMF_BUILD_LEVEL_ZERO_PROVIDER)
    include(FetchContent)

    set(LEVEL_ZERO_LOADER_REPO "https://github.com/oneapi-src/level-zero.git")
    set(LEVEL_ZERO_LOADER_TAG v1.16.1)

    FetchContent_Declare(
        level-zero-loader
        GIT_REPOSITORY ${LEVEL_ZERO_LOADER_REPO}
        GIT_TAG ${LEVEL_ZERO_LOADER_TAG}
        EXCLUDE_FROM_ALL)

    FetchContent_GetProperties(level-zero-loader)
    if(NOT level-zero-loader_POPULATED)
        FetchContent_Populate(level-zero-loader)
    endif()

    set(LEVEL_ZERO_INCLUDE_DIRS
        ${level-zero-loader_SOURCE_DIR}/include
        CACHE PATH "Path to Level Zero Headers")
    message(STATUS "Level Zero include directory: ${LEVEL_ZERO_INCLUDE_DIRS}")
endif()

add_subdirectory(utils)

set(UMF_LIBS $<BUILD_INTERFACE:umf_utils>)

set(BA_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/base_alloc/base_alloc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/base_alloc/base_alloc_linear.c
    ${CMAKE_CURRENT_SOURCE_DIR}/base_alloc/base_alloc_global.c)

if(LINUX)
    set(BA_SOURCES ${BA_SOURCES}
                   ${CMAKE_CURRENT_SOURCE_DIR}/base_alloc/base_alloc_linux.c)
elseif(WINDOWS)
    set(BA_SOURCES ${BA_SOURCES}
                   ${CMAKE_CURRENT_SOURCE_DIR}/base_alloc/base_alloc_windows.c)
elseif(MACOSX)
    set(BA_SOURCES ${BA_SOURCES}
                   ${CMAKE_CURRENT_SOURCE_DIR}/base_alloc/base_alloc_linux.c)
endif()

set(BA_SOURCES
    ${BA_SOURCES}
    PARENT_SCOPE)

set(UMF_SOURCES
    ${BA_SOURCES}
    memory_pool.c
    memory_provider.c
    memory_provider_get_last_failed.c
    memory_target.c
    memspace.c
    provider/provider_tracking.c
    critnib/critnib.c
    pool/pool_proxy.c
    topology.c)

set(UMF_SOURCES_LINUX libumf_linux.c)

set(UMF_SOURCES_WINDOWS libumf_windows.c)

# Compile definitions for UMF library.
#
# TODO: Cleanup the compile definitions across all the CMake files
set(UMF_PUBLIC_COMPILE_DEFINITIONS "")

set(UMF_SOURCES_LINUX
    ${UMF_SOURCES_LINUX}
    provider/provider_os_memory.c
    provider/provider_os_memory_linux.c
    memory_targets/memory_target_numa.c
    memspaces/memspace_numa.c
    memspaces/memspace_host_all.c
    memspaces/memspace_highest_capacity.c)

set(UMF_SOURCES_WINDOWS ${UMF_SOURCES_WINDOWS} provider/provider_os_memory.c
                        provider/provider_os_memory_windows.c)

set(UMF_LIBS ${UMF_LIBS} ${LIBHWLOC_LIBRARIES})
set(UMF_PRIVATE_LIBRARY_DIRS ${UMF_PRIVATE_LIBRARY_DIRS}
                             ${LIBHWLOC_LIBRARY_DIRS})

set(UMF_SOURCES_MACOSX ${UMF_SOURCES_MACOSX} ${UMF_SOURCES_LINUX})

if(LINUX)
    set(UMF_SOURCES ${UMF_SOURCES} ${UMF_SOURCES_LINUX})
elseif(WINDOWS)
    set(UMF_SOURCES ${UMF_SOURCES} ${UMF_SOURCES_WINDOWS})
elseif(MACOSX)
    set(UMF_SOURCES ${UMF_SOURCES} ${UMF_SOURCES_MACOSX})
endif()

if(UMF_BUILD_SHARED_LIBRARY)
    add_umf_library(
        NAME umf
        TYPE SHARED
        SRCS ${UMF_SOURCES}
        LIBS ${UMF_LIBS}
        LINUX_MAP_FILE ${CMAKE_CURRENT_SOURCE_DIR}/libumf.map
        WINDOWS_DEF_FILE ${CMAKE_CURRENT_SOURCE_DIR}/libumf.def)
    set(UMF_PUBLIC_COMPILE_DEFINITIONS ${UMF_PUBLIC_COMPILE_DEFINITIONS}
                                       "UMF_SHARED_LIBRARY")
    set_target_properties(umf PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                         ${CMAKE_UMF_OUTPUT_DIRECTORY})
else()
    add_umf_library(
        NAME umf
        TYPE STATIC
        SRCS ${UMF_SOURCES}
        LIBS ${UMF_LIBS})
endif()

if(UMF_ENABLE_POOL_TRACKING)
    set(UMF_PUBLIC_COMPILE_DEFINITIONS ${UMF_PUBLIC_COMPILE_DEFINITIONS}
                                       "UMF_ENABLE_POOL_TRACKING")
endif()

target_link_directories(umf PRIVATE ${UMF_PRIVATE_LIBRARY_DIRS})

target_compile_definitions(umf PUBLIC ${UMF_PUBLIC_COMPILE_DEFINITIONS})

if(UMF_BUILD_LEVEL_ZERO_PROVIDER)
    target_sources(umf PRIVATE provider/provider_level_zero.c)

    if(LINUX)
        # WA for error ze_api.h:14234:20: no newline at end of file
        # [-Werror,-Wnewline-eof]
        set_source_files_properties(
            provider/provider_level_zero.c
            PROPERTIES APPEND_STRING PROPERTY COMPILE_FLAGS "-Wno-newline-eof")
    endif()

    set(UMF_COMPILE_DEFINITIONS ${UMF_COMPILE_DEFINITIONS}
                                "UMF_BUILD_LEVEL_ZERO_PROVIDER=1")
endif()

add_library(${PROJECT_NAME}::umf ALIAS umf)

if(LIBHWLOC_INCLUDE_DIRS)
    target_include_directories(umf PRIVATE ${LIBHWLOC_INCLUDE_DIRS})
endif()

if(LEVEL_ZERO_INCLUDE_DIRS)
    target_include_directories(umf PRIVATE ${LEVEL_ZERO_INCLUDE_DIRS})
endif()

target_include_directories(
    umf
    PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/critnib>
           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/provider>
           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/memspaces>
           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/memory_targets>
           $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

install(TARGETS umf EXPORT ${PROJECT_NAME}-targets)

add_subdirectory(pool)

if(UMF_PROXY_LIB_ENABLED)
    add_subdirectory(proxy_lib)
endif()
