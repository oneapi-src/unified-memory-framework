# Copyright (C) 2023-2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

include(${UMF_CMAKE_SOURCE_DIR}/cmake/helpers.cmake)

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

if(UMF_BUILD_OS_MEMORY_PROVIDER)
    set(UMF_SOURCES_LINUX ${UMF_SOURCES_LINUX}
        provider/provider_os_memory.c
        provider/provider_os_memory_linux.c
        memory_targets/memory_target_numa.c
        memspaces/memspace_numa.c)
    if(LINUX)
        set(UMF_LIBS ${UMF_LIBS} hwloc)
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
    target_compile_definitions(umf PUBLIC UMF_SHARED_LIBRARY)
    set_target_properties(umf PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_UMF_OUTPUT_DIRECTORY})
else()
    add_umf_library(NAME umf
                    TYPE STATIC 
                    SRCS ${UMF_SOURCES} 
                    LIBS ${UMF_LIBS})
endif()

if (UMF_ENABLE_POOL_TRACKING)
    target_sources(umf PRIVATE memory_pool_tracking.c)
else()
    target_sources(umf PRIVATE memory_pool_default.c)
endif()

add_library(${PROJECT_NAME}::umf ALIAS umf)

target_include_directories(umf PUBLIC 
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/critnib>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/provider>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

install(TARGETS umf
    EXPORT ${PROJECT_NAME}-targets
)

add_subdirectory(pool)
