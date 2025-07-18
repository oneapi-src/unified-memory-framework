# Copyright (C) 2023-2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

include(${UMF_CMAKE_SOURCE_DIR}/cmake/helpers.cmake)

set(UMF_LEVEL_ZERO_INCLUDE_DIR
    ""
    CACHE PATH "Directory containing the Level Zero headers")
set(UMF_CUDA_INCLUDE_DIR
    ""
    CACHE PATH "Directory containing the CUDA headers")

# Compose the UMF_ALL_CMAKE_VARIABLES variable containing CMake options that
# will be saved in the constant string.
list(SORT UMF_OPTIONS_LIST ORDER DESCENDING)
foreach(_var ${UMF_OPTIONS_LIST})
    # Preprocessor definitions containing '#' cannot be passed on to the
    # compiler command line because many compilers do not support it.
    if(NOT "${${_var}}" MATCHES "#")
        set(UMF_ALL_CMAKE_VARIABLES
            "${_var}:${${_var}},${UMF_ALL_CMAKE_VARIABLES}")
    endif()
endforeach()

# Compile definitions for UMF library.
#
# TODO: Cleanup the compile definitions across all the CMake files
set(UMF_COMMON_COMPILE_DEFINITIONS
    ${UMF_COMMON_COMPILE_DEFINITIONS} UMF_VERSION=${UMF_VERSION}
    UMF_ALL_CMAKE_VARIABLES="${UMF_ALL_CMAKE_VARIABLES}")

add_subdirectory(utils)
add_subdirectory(base_alloc)
add_subdirectory(coarse)

set(UMF_LIBS umf_utils umf_ba umf_coarse $<BUILD_INTERFACE:${UMF_HWLOC_NAME}>)

set(UMF_SOURCES
    ctl/ctl.c
    libumf.c
    ipc.c
    ipc_cache.c
    memory_pool.c
    memory_props.c
    memory_provider.c
    memory_provider_get_last_failed.c
    memtarget.c
    memtargets/memtarget_numa.c
    mempolicy.c
    memspace.c
    memspaces/memspace_host_all.c
    memspaces/memspace_highest_capacity.c
    memspaces/memspace_highest_bandwidth.c
    memspaces/memspace_lowest_latency.c
    memspaces/memspace_numa.c
    provider/provider_cuda.c
    provider/provider_devdax_memory.c
    provider/provider_file_memory.c
    provider/provider_fixed_memory.c
    provider/provider_level_zero.c
    provider/provider_os_memory.c
    provider/provider_tracking.c
    critnib/critnib.c
    ravl/ravl.c
    pool/pool_disjoint.c
    pool/pool_jemalloc.c
    pool/pool_proxy.c
    pool/pool_scalable.c
    topology.c)

if(UMF_POOL_JEMALLOC_ENABLED)
    set(UMF_LIBS ${UMF_LIBS} ${JEMALLOC_LIBRARIES})
    set(UMF_PRIVATE_LIBRARY_DIRS ${UMF_PRIVATE_LIBRARY_DIRS}
                                 ${JEMALLOC_LIBRARY_DIRS})
    set(UMF_PRIVATE_INCLUDE_DIRS ${UMF_PRIVATE_INCLUDE_DIRS}
                                 ${JEMALLOC_INCLUDE_DIRS})
    set(UMF_COMMON_COMPILE_DEFINITIONS ${UMF_COMMON_COMPILE_DEFINITIONS}
                                       "UMF_POOL_JEMALLOC_ENABLED=1")
endif()

set(UMF_PRIVATE_LIBRARY_DIRS ${UMF_PRIVATE_LIBRARY_DIRS}
                             ${LIBHWLOC_LIBRARY_DIRS})

set(UMF_SOURCES_LINUX libumf_linux.c)
set(UMF_SOURCES_MACOSX libumf_linux.c)
set(UMF_SOURCES_WINDOWS libumf_windows.c)

if(UMF_BUILD_LEVEL_ZERO_PROVIDER)
    if(LINUX)
        # WA for error ze_api.h:14234:20: no newline at end of file
        # [-Werror,-Wnewline-eof]
        set_source_files_properties(
            provider/provider_level_zero.c
            PROPERTIES APPEND_STRING PROPERTY COMPILE_FLAGS "-Wno-newline-eof")
    endif()

    set(UMF_COMMON_COMPILE_DEFINITIONS ${UMF_COMMON_COMPILE_DEFINITIONS}
                                       "UMF_BUILD_LEVEL_ZERO_PROVIDER=1")
endif()

if(UMF_BUILD_CUDA_PROVIDER)
    set(UMF_COMMON_COMPILE_DEFINITIONS ${UMF_COMMON_COMPILE_DEFINITIONS}
                                       "UMF_BUILD_CUDA_PROVIDER=1")
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
    if(UMF_INSTALL_RPATH)
        set(CMAKE_INSTALL_RPATH "${UMF_INSTALL_RPATH}")
    endif()

    add_umf_library(
        NAME umf
        TYPE SHARED
        SRCS ${UMF_SOURCES}
        LIBS ${UMF_LIBS}
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

target_include_directories(umf PRIVATE ${UMF_PRIVATE_INCLUDE_DIRS})
target_link_directories(umf PRIVATE ${UMF_PRIVATE_LIBRARY_DIRS})
target_compile_definitions(umf PRIVATE ${UMF_COMMON_COMPILE_DEFINITIONS})

add_dependencies(umf umf_ba umf_coarse umf_utils)

if(UMF_LINK_HWLOC_STATICALLY)
    add_dependencies(umf ${UMF_HWLOC_NAME})
    # On Darwin, link with the IOKit and Foundation frameworks, if they are
    # available in the system. This is to comply with hwloc which links these,
    # if available. There is no option to disable these frameworks on Darwin
    # hwloc builds.
    if(MACOSX)
        find_library(IOKIT_LIBRARY IOKit)
        find_library(FOUNDATION_LIBRARY Foundation)
        if(IOKIT_LIBRARY OR FOUNDATION_LIBRARY)
            target_link_libraries(umf PRIVATE ${IOKIT_LIBRARY}
                                              ${FOUNDATION_LIBRARY})
        endif()
    endif()
endif()

if(NOT WINDOWS AND UMF_POOL_JEMALLOC_ENABLED)
    add_dependencies(umf jemalloc)
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
           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/uthash>
           $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

install(TARGETS umf EXPORT ${PROJECT_NAME}-targets)

if(UMF_PROXY_LIB_ENABLED)
    add_subdirectory(proxy_lib)
endif()
