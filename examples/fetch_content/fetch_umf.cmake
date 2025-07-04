# Copyright (C) 2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

message(STATUS "Downloading Unified Memory Framework ...")

include(FetchContent)

if(NOT DEFINED UMF_REPO)
    set(UMF_REPO "https://github.com/oneapi-src/unified-memory-framework.git")
elseif(WINDOWS)
    string(REPLACE "\\" "/" OUT_UMF_REPO "${UMF_REPO}")
    message(
        STATUS
            "Replaced \"${UMF_REPO}\" with \"${OUT_UMF_REPO}\" for Windows compatibility"
    )
    set(UMF_REPO "${OUT_UMF_REPO}")
endif()

if(NOT DEFINED UMF_TAG)
    set(UMF_TAG HEAD)
endif()

message(
    STATUS
        "Will fetch Unified Memory Framework from ${UMF_REPO} at ${UMF_TAG} ..."
)
message(STATUS "CMAKE_GENERATOR: ${CMAKE_GENERATOR}")

FetchContent_Declare(
    unified-memory-framework
    GIT_REPOSITORY ${UMF_REPO}
    GIT_TAG ${UMF_TAG})

set(UMF_BUILD_TESTS
    OFF
    CACHE INTERNAL "Do not build UMF tests")
set(UMF_BUILD_EXAMPLES
    OFF
    CACHE INTERNAL "Do not build UMF examples")
set(UMF_BUILD_SHARED_LIBRARY
    OFF
    CACHE INTERNAL "Build UMF shared library")
set(UMF_BUILD_LIBUMF_POOL_DISJOINT
    ON
    CACHE INTERNAL "Build Disjoint Pool")
set(UMF_BUILD_CUDA_PROVIDER
    OFF
    CACHE INTERNAL "Do not build CUDA provider")
set(UMF_BUILD_LEVEL_ZERO_PROVIDER
    OFF
    CACHE INTERNAL "Do not build L0 provider")
set(UMF_DISABLE_HWLOC
    OFF
    CACHE INTERNAL "Enable HWLOC support")
set(UMF_LINK_HWLOC_STATICALLY
    OFF
    CACHE INTERNAL "UMF_LINK_HWLOC_STATICALLY=OFF")

FetchContent_MakeAvailable(unified-memory-framework)
FetchContent_GetProperties(unified-memory-framework)

set(LIBUMF_INCLUDE_DIRS ${unified-memory-framework_SOURCE_DIR}/include)
set(LIBUMF_LIBRARIES umf::umf umf::headers)
