# Copyright (C) 2023 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# libumf_pool_disjoint
if(UMF_BUILD_LIBUMF_POOL_DISJOINT)
    add_umf_library(NAME disjoint_pool
                    TYPE STATIC
                    SRCS pool_disjoint.cpp)

    add_library(${PROJECT_NAME}::disjoint_pool ALIAS disjoint_pool)

    add_dependencies(disjoint_pool
        unified_memory_framework)

    target_link_libraries(disjoint_pool PRIVATE
        unified_memory_framework)

    target_include_directories(disjoint_pool PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include/umf/pools>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )

    install(TARGETS disjoint_pool
        EXPORT ${PROJECT_NAME}-targets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()
    
# libumf_pool_jemalloc
if(UMF_BUILD_LIBUMF_POOL_JEMALLOC)
    if(LINUX)
        add_umf_library(NAME pool_jemalloc TYPE STATIC SRCS pool_jemalloc.c LIBS jemalloc)
    else()
        message(FATAL_ERROR "libumf_pool_jemalloc is supported on Linux only")
    endif()
endif()
