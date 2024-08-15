# Copyright (C) 2023-2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

include(${UMF_CMAKE_SOURCE_DIR}/cmake/helpers.cmake)

set(PROXY_SOURCES proxy_lib.c)

set(PROXY_SOURCES_LINUX proxy_lib_linux.c)

set(PROXY_SOURCES_WINDOWS proxy_lib_windows.c)

set(PROXY_SOURCES_MACOSX proxy_lib_linux.c)

if(LINUX)
    set(PROXY_SOURCES ${PROXY_SOURCES} ${PROXY_SOURCES_LINUX})
elseif(WINDOWS)
    set(PROXY_SOURCES ${PROXY_SOURCES} ${PROXY_SOURCES_WINDOWS})

    # Add resource file needed for Windows to fill metadata in binary files
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/proxy_lib.rc.in"
                   "${CMAKE_CURRENT_BINARY_DIR}/proxy_lib.rc" IMMEDIATE @ONLY)
    set(PROXY_SOURCES ${PROXY_SOURCES} ${CMAKE_CURRENT_BINARY_DIR}/proxy_lib.rc)
elseif(MACOSX)
    set(PROXY_SOURCES ${PROXY_SOURCES} ${PROXY_SOURCES_MACOSX})
endif()

add_umf_library(
    NAME umf_proxy
    TYPE SHARED
    SRCS ${BA_SOURCES} ${PROXY_SOURCES}
    LIBS umf_utils ${PROXY_LIBS}
    LINUX_MAP_FILE ${CMAKE_CURRENT_SOURCE_DIR}/proxy_lib.map
    WINDOWS_DEF_FILE ${CMAKE_CURRENT_SOURCE_DIR}/proxy_lib.def)
set_target_properties(umf_proxy PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR})

add_library(${PROJECT_NAME}::proxy ALIAS umf_proxy)

target_link_directories(umf_proxy PRIVATE ${LIBHWLOC_LIBRARY_DIRS})

target_compile_definitions(umf_proxy PRIVATE ${UMF_COMMON_COMPILE_DEFINITIONS})

if(PROXY_LIB_USES_SCALABLE_POOL)
    target_compile_definitions(umf_proxy PRIVATE PROXY_LIB_USES_SCALABLE_POOL=1)
elseif(PROXY_LIB_USES_JEMALLOC_POOL)
    target_compile_definitions(umf_proxy PRIVATE PROXY_LIB_USES_JEMALLOC_POOL=1)
endif()

target_include_directories(
    umf_proxy
    PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
           $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/utils>
           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
           $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

install(TARGETS umf_proxy EXPORT ${PROJECT_NAME}-targets)
