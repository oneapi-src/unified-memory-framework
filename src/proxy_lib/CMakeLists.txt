# Copyright (C) 2023-2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

include(${UMF_CMAKE_SOURCE_DIR}/cmake/helpers.cmake)

set(UMF_PROXY_SOURCES_COMMON proxy_lib.c)
set(UMF_PROXY_SOURCES_LINUX proxy_lib_linux.c)
set(UMF_PROXY_SOURCES_WINDOWS proxy_lib_windows.c)

if(LINUX OR MACOSX)
    set(UMF_PROXY_SOURCES ${UMF_PROXY_SOURCES_COMMON}
                          ${UMF_PROXY_SOURCES_LINUX})
elseif(WINDOWS)
    set(UMF_PROXY_SOURCES ${UMF_PROXY_SOURCES_COMMON}
                          ${UMF_PROXY_SOURCES_WINDOWS})
    # Add resource file needed for Windows to fill metadata in binary files
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/proxy_lib.rc.in"
                   "${CMAKE_CURRENT_BINARY_DIR}/proxy_lib.rc" IMMEDIATE @ONLY)
    set(UMF_PROXY_SOURCES ${UMF_PROXY_SOURCES_COMMON}
                          ${CMAKE_CURRENT_BINARY_DIR}/proxy_lib.rc)
endif()

add_umf_library(
    NAME umf_proxy
    TYPE SHARED
    SRCS ${UMF_PROXY_SOURCES}
    LIBS umf umf_utils umf_ba
    LINUX_MAP_FILE ${CMAKE_CURRENT_SOURCE_DIR}/proxy_lib.map
    WINDOWS_DEF_FILE ${CMAKE_CURRENT_SOURCE_DIR}/proxy_lib.def)

set_target_properties(umf_proxy PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR})

if(PROXY_LIB_USES_SCALABLE_POOL)
    target_compile_definitions(umf_proxy
                               PRIVATE "PROXY_LIB_USES_SCALABLE_POOL=1")
elseif(PROXY_LIB_USES_JEMALLOC_POOL)
    target_compile_definitions(umf_proxy
                               PRIVATE "PROXY_LIB_USES_JEMALLOC_POOL=1")
endif()

target_include_directories(
    umf_proxy PRIVATE ${UMF_CMAKE_SOURCE_DIR}/src/base_alloc
                      ${UMF_CMAKE_SOURCE_DIR}/src/ravl)

install(TARGETS umf_proxy EXPORT ${PROJECT_NAME}-targets)
