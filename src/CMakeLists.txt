# Copyright (C) 2023-2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

include(${UMF_CMAKE_SOURCE_DIR}/cmake/helpers.cmake)

# set UMF_PROXY_LIB_BASED_ON_POOL to one of:
# - SCALABLE
# - JEMALLOC
set(UMF_PROXY_LIB_BASED_ON_POOL SCALABLE CACHE STRING "A UMF pool the proxy library is based on (SCALABLE or JEMALLOC)" FORCE)

add_subdirectory(utils)

set(UMF_LIBS umf_utils)

set(BA_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/base_alloc/base_alloc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/base_alloc/base_alloc_linear.c
    ${CMAKE_CURRENT_SOURCE_DIR}/base_alloc/base_alloc_global.c)

if (LINUX)
    set(BA_SOURCES ${BA_SOURCES} ${CMAKE_CURRENT_SOURCE_DIR}/base_alloc/base_alloc_linux.c)
elseif(WINDOWS)
    set(BA_SOURCES ${BA_SOURCES} ${CMAKE_CURRENT_SOURCE_DIR}/base_alloc/base_alloc_windows.c)
elseif(MACOSX)
    set(BA_SOURCES ${BA_SOURCES} ${CMAKE_CURRENT_SOURCE_DIR}/base_alloc/base_alloc_linux.c)
endif()

set(BA_SOURCES ${BA_SOURCES} PARENT_SCOPE)

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
)

set(UMF_SOURCES_LINUX
    libumf_linux.c
)

set(UMF_SOURCES_WINDOWS
    libumf_windows.c
)

set(UMF_SOURCES_MACOSX
    libumf_linux.c
)

# Compile definitions for UMF library
# TODO: Cleanup the compile definitions across all the Cmake files
set(UMF_COMPILE_DEFINITIONS "")

if(UMF_BUILD_OS_MEMORY_PROVIDER)
    set(UMF_SOURCES_LINUX ${UMF_SOURCES_LINUX}
        provider/provider_os_memory.c
        provider/provider_os_memory_linux.c
        memory_targets/memory_target_numa.c
        memspaces/memspace_numa.c
        memspaces/memspace_host_all.c)

    if(LINUX)
        if(PkgConfig_FOUND)
            pkg_check_modules(LIBHWLOC hwloc)
        endif()
        if(NOT LIBHWLOC_FOUND)
            find_package(LIBHWLOC REQUIRED hwloc)
        endif()
        set(UMF_LIBS ${UMF_LIBS} ${LIBHWLOC_LIBRARIES})
        # Currently, OS provider is only built for Linux
        set(UMF_COMPILE_DEFINITIONS ${UMF_COMPILE_DEFINITIONS} "UMF_BUILD_OS_MEMORY_PROVIDER=1")
    endif()
endif()

if(LINUX)
    set(UMF_SOURCES ${UMF_SOURCES} ${UMF_SOURCES_LINUX})
elseif(WINDOWS)
    set(UMF_SOURCES ${UMF_SOURCES} ${UMF_SOURCES_WINDOWS})
elseif(MACOSX)
    set(UMF_SOURCES ${UMF_SOURCES} ${UMF_SOURCES_MACOSX})
endif()

if(UMF_BUILD_SHARED_LIBRARY)
    add_umf_library(NAME umf
                    TYPE SHARED
                    SRCS ${UMF_SOURCES}
                    LIBS ${UMF_LIBS}
                    LINUX_MAP_FILE ${CMAKE_CURRENT_SOURCE_DIR}/libumf.map
                    WINDOWS_DEF_FILE ${CMAKE_CURRENT_SOURCE_DIR}/libumf.def)
    set(UMF_COMPILE_DEFINITIONS ${UMF_COMPILE_DEFINITIONS} "UMF_SHARED_LIBRARY")
    set_target_properties(umf PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_UMF_OUTPUT_DIRECTORY})
else()
    add_umf_library(NAME umf
                    TYPE STATIC
                    SRCS ${UMF_SOURCES}
                    LIBS ${UMF_LIBS})
endif()

target_compile_definitions(umf PUBLIC ${UMF_COMPILE_DEFINITIONS})

if (UMF_ENABLE_POOL_TRACKING)
    target_sources(umf PRIVATE memory_pool_tracking.c)
else()
    target_sources(umf PRIVATE memory_pool_default.c)
endif()

add_library(${PROJECT_NAME}::umf ALIAS umf)

target_include_directories(umf PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/critnib>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/provider>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/memspaces>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/memory_targets>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

install(TARGETS umf
    EXPORT ${PROJECT_NAME}-targets
)

add_subdirectory(pool)

# TODO: enable proxy_lib on Windows
if(LINUX)
    if(UMF_PROXY_LIB_BASED_ON_POOL STREQUAL SCALABLE)
        set(PROXY_LIB_USES_SCALABLE_POOL ON)
        set(PROXY_LIBS umf scalable_pool)
        if(UMF_BUILD_LIBUMF_POOL_SCALABLE)
            add_subdirectory(proxy_lib)
        else()
            message(STATUS "Disabling the proxy library, because UMF_PROXY_LIB_BASED_ON_POOL==SCALABLE but UMF_BUILD_LIBUMF_POOL_SCALABLE is OFF")
        endif()
    elseif(UMF_PROXY_LIB_BASED_ON_POOL STREQUAL JEMALLOC)
        set(PROXY_LIB_USES_JEMALLOC_POOL ON)
        set(PROXY_LIBS umf jemalloc_pool)
        if(UMF_BUILD_LIBUMF_POOL_JEMALLOC)
            add_subdirectory(proxy_lib)
        else()
            message(STATUS "Disabling the proxy library, because UMF_PROXY_LIB_BASED_ON_POOL==JEMALLOC but UMF_BUILD_LIBUMF_POOL_JEMALLOC is OFF")
        endif()
    else()
        message(FATAL_ERROR "Proxy library: pool manager not chosen or set to a non-supported one (see UMF_PROXY_LIB_BASED_ON_POOL)")
    endif()
endif()
