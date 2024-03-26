# Copyright (C) 2023 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

if(UMF_BUILD_SHARED_LIBRARY)
    set(POOL_EXTRA_SRCS ${BA_SOURCES})
    set(POOL_COMPILE_DEFINITIONS UMF_SHARED_LIBRARY)
    set(POOL_EXTRA_LIBS $<BUILD_INTERFACE:umf_utils>)
endif()

# libumf_pool_disjoint
if(UMF_BUILD_LIBUMF_POOL_DISJOINT)
    add_umf_library(
        NAME disjoint_pool
        TYPE STATIC
        SRCS pool_disjoint.cpp ${POOL_EXTRA_SRCS}
        LIBS ${POOL_EXTRA_LIBS})
    target_compile_definitions(disjoint_pool PUBLIC ${POOL_COMPILE_DEFINITIONS})

    add_library(${PROJECT_NAME}::disjoint_pool ALIAS disjoint_pool)

    add_dependencies(disjoint_pool umf)

    target_link_libraries(disjoint_pool PRIVATE umf)

    target_include_directories(
        disjoint_pool
        PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include/umf/pools>
               $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

    install(TARGETS disjoint_pool EXPORT ${PROJECT_NAME}-targets)
endif()

# libumf_pool_jemalloc
if(UMF_BUILD_LIBUMF_POOL_JEMALLOC)
    add_umf_library(
        NAME jemalloc_pool
        TYPE STATIC
        SRCS pool_jemalloc.c ${POOL_EXTRA_SRCS}
        LIBS jemalloc ${POOL_EXTRA_LIBS})
    target_include_directories(jemalloc_pool PRIVATE ${JEMALLOC_INCLUDE_DIRS})
    target_compile_definitions(jemalloc_pool PUBLIC ${POOL_COMPILE_DEFINITIONS})
    add_library(${PROJECT_NAME}::jemalloc_pool ALIAS jemalloc_pool)
    install(TARGETS jemalloc_pool EXPORT ${PROJECT_NAME}-targets)
endif()

# libumf_pool_scalable
if(UMF_BUILD_LIBUMF_POOL_SCALABLE)
    if(LINUX)
        set(LIBS_POOL_SCALABLE dl ${POOL_EXTRA_LIBS})
    else()
        set(LIBS_POOL_SCALABLE ${POOL_EXTRA_LIBS})
    endif()

    add_umf_library(
        NAME scalable_pool
        TYPE STATIC
        SRCS pool_scalable.c ${POOL_EXTRA_SRCS}
        LIBS ${LIBS_POOL_SCALABLE})
    target_include_directories(scalable_pool PRIVATE ${TBB_INCLUDE_DIRS})
    target_compile_definitions(scalable_pool PUBLIC ${POOL_COMPILE_DEFINITIONS})
    add_library(${PROJECT_NAME}::scalable_pool ALIAS scalable_pool)
    install(TARGETS scalable_pool EXPORT ${PROJECT_NAME}-targets)
endif()
