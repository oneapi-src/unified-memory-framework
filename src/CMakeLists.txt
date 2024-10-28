# Copyright (C) 2023-2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

include(${UMF_CMAKE_SOURCE_DIR}/cmake/helpers.cmake)

set(UMF_LEVEL_ZERO_INCLUDE_DIR
    ""
    CACHE PATH "Directory containing the Level Zero headers")
set(UMF_CUDA_INCLUDE_DIR
    ""
    CACHE PATH "Directory containing the CUDA headers")

# Compile definitions for UMF library.
#
# TODO: Cleanup the compile definitions across all the CMake files
set(UMF_COMMON_COMPILE_DEFINITIONS UMF_VERSION=${UMF_VERSION})

# Fetch L0 loader only if needed i.e.: if building L0 provider is ON and L0
# headers are not provided by the user (via setting UMF_LEVEL_ZERO_INCLUDE_DIR).
if(UMF_BUILD_LEVEL_ZERO_PROVIDER AND (NOT UMF_LEVEL_ZERO_INCLUDE_DIR))
    include(FetchContent)

    set(LEVEL_ZERO_LOADER_REPO "https://github.com/oneapi-src/level-zero.git")
    set(LEVEL_ZERO_LOADER_TAG v1.17.39)

    message(
        STATUS
            "Fetching L0 loader (${LEVEL_ZERO_LOADER_TAG}) from ${LEVEL_ZERO_LOADER_REPO} ..."
    )

    FetchContent_Declare(
        level-zero-loader
        GIT_REPOSITORY ${LEVEL_ZERO_LOADER_REPO}
        GIT_TAG ${LEVEL_ZERO_LOADER_TAG}
        EXCLUDE_FROM_ALL)
    FetchContent_MakeAvailable(level-zero-loader)

    set(LEVEL_ZERO_INCLUDE_DIRS
        ${level-zero-loader_SOURCE_DIR}/include
        CACHE PATH "Path to Level Zero Headers")
    message(STATUS "Level Zero include directory: ${LEVEL_ZERO_INCLUDE_DIRS}")
elseif(UMF_BUILD_LEVEL_ZERO_PROVIDER)
    # Only header is needed to build UMF
    set(LEVEL_ZERO_INCLUDE_DIRS ${UMF_LEVEL_ZERO_INCLUDE_DIR})
    message(STATUS "Level Zero include directory: ${LEVEL_ZERO_INCLUDE_DIRS}")
endif()

# Fetch CUDA only if needed i.e.: if building CUDA provider is ON and CUDA
# headers are not provided by the user (via setting UMF_CUDA_INCLUDE_DIR).
if(UMF_BUILD_CUDA_PROVIDER AND (NOT UMF_CUDA_INCLUDE_DIR))
    include(FetchContent)

    set(CUDA_REPO
        "https://gitlab.com/nvidia/headers/cuda-individual/cudart.git")
    set(CUDA_TAG cuda-12.5.1)

    message(STATUS "Fetching CUDA ${CUDA_TAG} from ${CUDA_REPO} ...")

    FetchContent_Declare(
        cuda-headers
        GIT_REPOSITORY ${CUDA_REPO}
        GIT_TAG ${CUDA_TAG}
        EXCLUDE_FROM_ALL)
    FetchContent_MakeAvailable(cuda-headers)

    set(CUDA_INCLUDE_DIRS
        ${cuda-headers_SOURCE_DIR}
        CACHE PATH "Path to CUDA headers")
    message(STATUS "CUDA include directory: ${CUDA_INCLUDE_DIRS}")
elseif(UMF_BUILD_CUDA_PROVIDER)
    # Only header is needed to build UMF
    set(CUDA_INCLUDE_DIRS ${UMF_CUDA_INCLUDE_DIR})
    message(STATUS "CUDA include directory: ${CUDA_INCLUDE_DIRS}")
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

set(HWLOC_DEPENDENT_SOURCES topology.c)

set(UMF_SOURCES
    ${BA_SOURCES}
    libumf.c
    ipc.c
    memory_pool.c
    memory_provider.c
    memory_provider_get_last_failed.c
    memtarget.c
    mempolicy.c
    memspace.c
    memspaces/memspace_host_all.c
    memspaces/memspace_highest_capacity.c
    memspaces/memspace_highest_bandwidth.c
    memspaces/memspace_lowest_latency.c
    memspaces/memspace_numa.c
    provider/provider_coarse.c
    provider/provider_cuda.c
    provider/provider_devdax_memory.c
    provider/provider_file_memory.c
    provider/provider_level_zero.c
    provider/provider_os_memory.c
    provider/provider_tracking.c
    critnib/critnib.c
    ravl/ravl.c
    pool/pool_proxy.c
    pool/pool_scalable.c)

if(NOT UMF_DISABLE_HWLOC)
    set(UMF_SOURCES ${UMF_SOURCES} ${HWLOC_DEPENDENT_SOURCES}
                    memtargets/memtarget_numa.c)
    set(UMF_LIBS ${UMF_LIBS} ${LIBHWLOC_LIBRARIES})
    set(UMF_PRIVATE_LIBRARY_DIRS ${UMF_PRIVATE_LIBRARY_DIRS}
                                 ${LIBHWLOC_LIBRARY_DIRS})
else()
    set(UMF_COMMON_COMPILE_DEFINITIONS ${UMF_COMMON_COMPILE_DEFINITIONS}
                                       "UMF_NO_HWLOC=1")
endif()

set(UMF_SOURCES_LINUX libumf_linux.c)
set(UMF_SOURCES_MACOSX libumf_linux.c)
set(UMF_SOURCES_WINDOWS libumf_windows.c)

# Add compile definitions to handle unsupported functions
if(NOT UMF_BUILD_CUDA_PROVIDER)
    set(UMF_COMMON_COMPILE_DEFINITIONS ${UMF_COMMON_COMPILE_DEFINITIONS}
                                       "UMF_NO_CUDA_PROVIDER=1")
endif()
if(NOT UMF_BUILD_LEVEL_ZERO_PROVIDER)
    set(UMF_COMMON_COMPILE_DEFINITIONS ${UMF_COMMON_COMPILE_DEFINITIONS}
                                       "UMF_NO_LEVEL_ZERO_PROVIDER=1")
endif()
if(UMF_DISABLE_HWLOC OR WINDOWS)
    set(UMF_COMMON_COMPILE_DEFINITIONS ${UMF_COMMON_COMPILE_DEFINITIONS}
                                       "UMF_NO_DEVDAX_PROVIDER=1")
    set(UMF_COMMON_COMPILE_DEFINITIONS ${UMF_COMMON_COMPILE_DEFINITIONS}
                                       "UMF_NO_FILE_PROVIDER=1")
endif()

if(LINUX)
    set(UMF_SOURCES ${UMF_SOURCES} ${UMF_SOURCES_LINUX})
    set(UMF_LIBS ${UMF_LIBS} dl)
elseif(WINDOWS)
    set(UMF_SOURCES ${UMF_SOURCES} ${UMF_SOURCES_WINDOWS})

    # Add resource file needed for Windows to fill metadata in binary files
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/libumf.rc.in"
                   "${CMAKE_CURRENT_BINARY_DIR}/libumf.rc" IMMEDIATE @ONLY)
    set(UMF_SOURCES ${UMF_SOURCES} ${CMAKE_CURRENT_BINARY_DIR}/libumf.rc)
elseif(MACOSX)
    set(UMF_SOURCES ${UMF_SOURCES} ${UMF_SOURCES_MACOSX})
endif()

if(UMF_BUILD_SHARED_LIBRARY)
    if(NOT UMF_DISABLE_HWLOC)
        set(HWLOC_LIB ${UMF_HWLOC_NAME})
    endif()
    add_umf_library(
        NAME umf
        TYPE SHARED
        SRCS ${UMF_SOURCES}
        LIBS ${UMF_LIBS} ${HWLOC_LIB}
        LINUX_MAP_FILE ${CMAKE_CURRENT_SOURCE_DIR}/libumf.map
        WINDOWS_DEF_FILE ${CMAKE_CURRENT_SOURCE_DIR}/libumf.def)
    set(UMF_COMMON_COMPILE_DEFINITIONS ${UMF_COMMON_COMPILE_DEFINITIONS}
                                       "UMF_SHARED_LIBRARY")
    set_target_properties(
        umf
        PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_UMF_OUTPUT_DIRECTORY}
                   VERSION ${PROJECT_VERSION}
                   SOVERSION ${PROJECT_VERSION_MAJOR})
else()
    add_umf_library(
        NAME umf
        TYPE STATIC
        SRCS ${UMF_SOURCES}
        LIBS ${UMF_LIBS})
endif()

if(UMF_LINK_HWLOC_STATICALLY)
    add_dependencies(umf ${UMF_HWLOC_NAME})
endif()

target_link_directories(umf PRIVATE ${UMF_PRIVATE_LIBRARY_DIRS})

target_compile_definitions(umf PRIVATE ${UMF_COMMON_COMPILE_DEFINITIONS})

if(UMF_BUILD_LEVEL_ZERO_PROVIDER)
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

if(UMF_BUILD_CUDA_PROVIDER)
    set(UMF_COMPILE_DEFINITIONS ${UMF_COMPILE_DEFINITIONS}
                                "UMF_BUILD_CUDA_PROVIDER=1")
endif()

add_library(${PROJECT_NAME}::umf ALIAS umf)

if(LIBHWLOC_INCLUDE_DIRS)
    target_include_directories(umf PRIVATE ${LIBHWLOC_INCLUDE_DIRS})
endif()

if(LEVEL_ZERO_INCLUDE_DIRS)
    target_include_directories(umf PRIVATE ${LEVEL_ZERO_INCLUDE_DIRS})
endif()

if(CUDA_INCLUDE_DIRS)
    target_include_directories(umf PRIVATE ${CUDA_INCLUDE_DIRS})
endif()

target_include_directories(
    umf
    PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/ravl>
           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/critnib>
           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/provider>
           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/memspaces>
           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/memtargets>
           $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

install(TARGETS umf EXPORT ${PROJECT_NAME}-targets)

add_subdirectory(pool)

if(UMF_PROXY_LIB_ENABLED
   AND NOT UMF_LINK_HWLOC_STATICALLY
   AND NOT UMF_DISABLE_HWLOC)
    add_subdirectory(proxy_lib)
endif()
