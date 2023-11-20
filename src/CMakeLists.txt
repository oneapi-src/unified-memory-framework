# Copyright (C) 2023 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

include(../cmake/helpers.cmake)

set(UMF_SOURCES
    memory_pool.c
    memory_provider.c
    memory_provider_get_last_failed.c
    pool/pool_disjoint.cpp
    provider/provider_tracking.c
    critnib/critnib.c
)

if(MSVC)
    set(UMF_SOURCES ${UMF_SOURCES} utils/utils_windows.c provider/provider_tracking_windows.cpp)
else()
    set(UMF_SOURCES ${UMF_SOURCES} utils/utils_posix.c)
endif()

if(UMF_BUILD_SHARED_LIBRARY)
    add_umf_library(unified_memory_framework SHARED ${UMF_SOURCES})
    target_compile_definitions(unified_memory_framework PUBLIC UMF_SHARED_LIBRARY)
else()
    add_umf_library(unified_memory_framework STATIC ${UMF_SOURCES})
endif()

if (UMF_ENABLE_POOL_TRACKING)
    target_sources(unified_memory_framework PRIVATE memory_pool_tracking.c)
else()
    target_sources(unified_memory_framework PRIVATE memory_pool_default.c)
endif()

add_library(${PROJECT_NAME}::unified_memory_framework ALIAS unified_memory_framework)

target_include_directories(unified_memory_framework PUBLIC ../include ./common ./provider ./critnib)
