# Copyright (C) 2023 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

include(${UMF_CMAKE_SOURCE_DIR}/cmake/helpers.cmake)

set(UMF_SOURCES
    memory_pool.c
    memory_provider.c
    memory_provider_get_last_failed.c
    provider/provider_os_memory.c
    provider/provider_tracking.c
    critnib/critnib.c
)

set(UMF_SOURCES_LINUX
    provider/provider_os_memory_linux.c
    utils/utils_posix_concurrency.c
    utils/utils_posix_math.c
)

set(UMF_SOURCES_WINDOWS
    provider/provider_os_memory_windows.c
    provider/provider_tracking_windows.cpp
    utils/utils_windows_concurrency.c
    utils/utils_windows_math.c
)

set(UMF_SOURCES_MACOSX
    utils/utils_posix_concurrency.c
    utils/utils_posix_math.c
)

if(LINUX)
    set(UMF_LIBS numa)
else()
    set(UMF_LIBS)
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
                    LIBS ${UMF_LIBS})
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
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/common>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/critnib>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/provider>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/utils>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

install(TARGETS umf
    EXPORT ${PROJECT_NAME}-targets
)

add_subdirectory(pool)
