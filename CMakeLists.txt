# Copyright (C) 2022-2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14.0 FATAL_ERROR)
# needed when UMF is used as an external project
set(UMF_CMAKE_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

list(APPEND CMAKE_MODULE_PATH "${UMF_CMAKE_SOURCE_DIR}/cmake")
# Use full path of the helpers module (to omit potential conflicts with others)
include(${UMF_CMAKE_SOURCE_DIR}/cmake/helpers.cmake)

# We use semver aligned version, set via git tags. We parse git output to
# establih the version of UMF to be used in CMake, Win dll's, and within the
# code (e.g. in logger). We have 3-component releases (e.g. 1.5.1) plus release
# candidates and git info. Function below sets all variables related to version.
set_version_variables()
message(STATUS "UMF version: ${UMF_VERSION}")

# version we set in CMake is abbreviated just to major.minor.patch
project(
    umf
    VERSION ${UMF_CMAKE_VERSION}
    LANGUAGES C)

if(PROJECT_VERSION_PATCH GREATER 0)
    # set extra variable for Windows dll metadata
    set(UMF_VERSION_BUGFIX 1)
endif()

include(CTest)
include(CMakePackageConfigHelpers)
include(GNUInstallDirs)
find_package(PkgConfig)

# Build Options
option(UMF_BUILD_SHARED_LIBRARY "Build UMF as shared library" OFF)
option(UMF_BUILD_LEVEL_ZERO_PROVIDER "Build Level Zero memory provider" ON)
option(UMF_BUILD_CUDA_PROVIDER "Build CUDA memory provider" ON)
option(UMF_BUILD_LIBUMF_POOL_DISJOINT
       "Build the libumf_pool_disjoint static library" OFF)
option(UMF_BUILD_LIBUMF_POOL_JEMALLOC
       "Build the libumf_pool_jemalloc static library" OFF)
option(UMF_BUILD_TESTS "Build UMF tests" ON)
option(UMF_BUILD_GPU_TESTS "Build UMF GPU tests" OFF)
option(UMF_BUILD_BENCHMARKS "Build UMF benchmarks" OFF)
option(UMF_BUILD_BENCHMARKS_MT "Build UMF multithreaded benchmarks" OFF)
option(UMF_BUILD_EXAMPLES "Build UMF examples" ON)
option(UMF_BUILD_FUZZTESTS "Build UMF fuzz tests" OFF)
option(UMF_BUILD_GPU_EXAMPLES "Build UMF GPU examples" OFF)
option(UMF_DEVELOPER_MODE "Enable additional developer checks" OFF)
option(
    UMF_DISABLE_HWLOC
    "Disable hwloc and UMF features requiring it (OS provider, memtargets, topology discovery)"
    OFF)
option(
    UMF_LINK_HWLOC_STATICALLY
    "Link UMF with HWLOC library statically (supported for Linux, MacOS and Release build on Windows)"
    OFF)
option(UMF_FORMAT_CODE_STYLE
       "Add clang, cmake, and black -format-check and -format-apply targets"
       OFF)
set(UMF_HWLOC_NAME
    "hwloc"
    CACHE STRING "Custom name for hwloc library w/o extension")
set(UMF_INSTALL_RPATH
    ""
    CACHE
        STRING
        "Set the runtime search path to the directory with dependencies (e.g. hwloc)"
)

# Only a part of skips is treated as a failure now. TODO: extend to all tests
option(UMF_TESTS_FAIL_ON_SKIP "Treat skips in tests as fail" OFF)
option(UMF_USE_ASAN "Enable AddressSanitizer checks" OFF)
option(UMF_USE_UBSAN "Enable UndefinedBehaviorSanitizer checks" OFF)
option(UMF_USE_TSAN "Enable ThreadSanitizer checks" OFF)
option(UMF_USE_MSAN "Enable MemorySanitizer checks" OFF)
option(UMF_USE_VALGRIND "Enable Valgrind instrumentation" OFF)
option(UMF_USE_COVERAGE "Build with coverage enabled (Linux only)" OFF)

# set UMF_PROXY_LIB_BASED_ON_POOL to one of: SCALABLE or JEMALLOC
set(KNOWN_PROXY_LIB_POOLS SCALABLE JEMALLOC)
set(UMF_PROXY_LIB_BASED_ON_POOL
    SCALABLE
    CACHE STRING
          "A UMF pool the proxy library is based on (SCALABLE or JEMALLOC)")
set_property(CACHE UMF_PROXY_LIB_BASED_ON_POOL
             PROPERTY STRINGS ${KNOWN_PROXY_LIB_POOLS})

if(UMF_BUILD_TESTS
   AND DEFINED ENV{CI}
   AND NOT UMF_TESTS_FAIL_ON_SKIP)
    message(
        FATAL_ERROR
            "Env variable 'CI' is set, tests are enabled, but UMF_TESTS_FAIL_ON_SKIP is not. "
            "Please set UMF_TESTS_FAIL_ON_SKIP to ON in all CI workflows running tests."
    )
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(LINUX TRUE)
    set(OS_NAME "linux")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set(WINDOWS TRUE)
    set(OS_NAME "windows")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set(MACOSX TRUE)
    set(OS_NAME "macosx")
else()
    message(FATAL_ERROR "Unknown OS type")
endif()

if(NOT UMF_BUILD_LIBUMF_POOL_JEMALLOC)
    set(UMF_POOL_JEMALLOC_ENABLED FALSE)
    set(JEMALLOC_FOUND FALSE)
    set(JEMALLOC_LIBRARIES FALSE)
elseif(WINDOWS)
    pkg_check_modules(JEMALLOC jemalloc)
    if(NOT JEMALLOC_FOUND)
        find_package(JEMALLOC REQUIRED jemalloc)
    endif()
else()
    if(NOT DEFINED UMF_JEMALLOC_REPO)
        set(UMF_JEMALLOC_REPO "https://github.com/jemalloc/jemalloc.git")
    endif()

    if(NOT DEFINED UMF_JEMALLOC_TAG)
        set(UMF_JEMALLOC_TAG 5.3.0)
    endif()

    include(FetchContent)
    message(
        STATUS
            "Will fetch jemalloc from ${UMF_JEMALLOC_REPO} (tag: ${UMF_JEMALLOC_TAG})"
    )

    FetchContent_Declare(
        jemalloc_targ
        GIT_REPOSITORY ${UMF_JEMALLOC_REPO}
        GIT_TAG ${UMF_JEMALLOC_TAG})
    FetchContent_MakeAvailable(jemalloc_targ)

    add_custom_command(
        COMMAND ./autogen.sh
        WORKING_DIRECTORY ${jemalloc_targ_SOURCE_DIR}
        OUTPUT ${jemalloc_targ_SOURCE_DIR}/configure)
    add_custom_command(
        # Custom jemalloc build. Non-default options used:
        # --with-jemalloc-prefix=je_ - add je_ prefix to all public APIs
        # --disable-cxx - Disable C++ integration. This will cause new and
        # delete operators implementations to be omitted.
        # --disable-initial-exec-tls - Disable the initial-exec TLS model for
        # jemalloc's internal thread-local storage (on those platforms that
        # support explicit settings). This can allow jemalloc to be dynamically
        # loaded after program startup (e.g. using dlopen).
        COMMAND
            ./configure --prefix=${jemalloc_targ_BINARY_DIR}
            --with-jemalloc-prefix=je_ --disable-cxx --disable-initial-exec-tls
            CFLAGS=-fPIC
        WORKING_DIRECTORY ${jemalloc_targ_SOURCE_DIR}
        OUTPUT ${jemalloc_targ_SOURCE_DIR}/Makefile
        DEPENDS ${jemalloc_targ_SOURCE_DIR}/configure)
    add_custom_command(
        COMMAND make
        WORKING_DIRECTORY ${jemalloc_targ_SOURCE_DIR}
        OUTPUT ${jemalloc_targ_SOURCE_DIR}/lib/libjemalloc.a
        DEPENDS ${jemalloc_targ_SOURCE_DIR}/Makefile)
    add_custom_command(
        COMMAND make install
        WORKING_DIRECTORY ${jemalloc_targ_SOURCE_DIR}
        OUTPUT ${jemalloc_targ_BINARY_DIR}/lib/libjemalloc.a
        DEPENDS ${jemalloc_targ_SOURCE_DIR}/lib/libjemalloc.a)

    add_custom_target(jemalloc_prod
                      DEPENDS ${jemalloc_targ_BINARY_DIR}/lib/libjemalloc.a)
    add_library(jemalloc INTERFACE)
    target_link_libraries(
        jemalloc INTERFACE ${jemalloc_targ_BINARY_DIR}/lib/libjemalloc.a)
    add_dependencies(jemalloc jemalloc_prod)

    set(JEMALLOC_LIBRARY_DIRS ${jemalloc_targ_BINARY_DIR}/lib)
    set(JEMALLOC_INCLUDE_DIRS ${jemalloc_targ_BINARY_DIR}/include)
    set(JEMALLOC_LIBRARIES ${jemalloc_targ_BINARY_DIR}/lib/libjemalloc.a)
endif()

if(JEMALLOC_FOUND OR JEMALLOC_LIBRARIES)
    set(UMF_POOL_JEMALLOC_ENABLED TRUE)
    # add PATH to DLL on Windows
    set(DLL_PATH_LIST
        "${DLL_PATH_LIST};PATH=path_list_append:${JEMALLOC_DLL_DIRS}")
    message(STATUS "    JEMALLOC_LIBRARIES = ${JEMALLOC_LIBRARIES}")
    message(STATUS "    JEMALLOC_INCLUDE_DIRS = ${JEMALLOC_INCLUDE_DIRS}")
    message(STATUS "    JEMALLOC_LIBRARY_DIRS = ${JEMALLOC_LIBRARY_DIRS}")
else()
    set(UMF_POOL_JEMALLOC_ENABLED FALSE)
    message(
        STATUS
            "Disabling the Jemalloc Pool and tests and benchmarks that use it because jemalloc was not built/found."
    )
endif()

if(UMF_DISABLE_HWLOC)
    message(STATUS "hwloc is disabled, hence OS provider, memtargets, "
                   "topology discovery, examples won't be available!")
else()
    if(NOT DEFINED UMF_HWLOC_REPO)
        set(UMF_HWLOC_REPO "https://github.com/open-mpi/hwloc.git")
    endif()

    if(NOT DEFINED UMF_HWLOC_TAG)
        set(UMF_HWLOC_TAG hwloc-2.10.0)
    endif()

    if(NOT UMF_LINK_HWLOC_STATICALLY)
        pkg_check_modules(LIBHWLOC hwloc>=2.3.0)
        if(NOT LIBHWLOC_FOUND)
            find_package(LIBHWLOC 2.3.0 REQUIRED hwloc)
        endif()

        # add PATH to DLL on Windows
        set(DLL_PATH_LIST
            "${DLL_PATH_LIST};PATH=path_list_append:${LIBHWLOC_DLL_DIRS}")
    elseif(WINDOWS)
        include(FetchContent)
        set(HWLOC_ENABLE_TESTING OFF)
        set(HWLOC_SKIP_LSTOPO ON)
        set(HWLOC_SKIP_TOOLS ON)

        message(
            STATUS
                "Will fetch hwloc from ${UMF_HWLOC_REPO} (tag: ${UMF_HWLOC_TAG})"
        )

        FetchContent_Declare(
            hwloc_targ
            GIT_REPOSITORY ${UMF_HWLOC_REPO}
            GIT_TAG ${UMF_HWLOC_TAG}
            SOURCE_SUBDIR contrib/windows-cmake/ FIND_PACKAGE_ARGS)
        FetchContent_MakeAvailable(hwloc_targ)

        set(LIBHWLOC_INCLUDE_DIRS
            ${hwloc_targ_SOURCE_DIR}/include;${hwloc_targ_BINARY_DIR}/include)
        set(LIBHWLOC_LIBRARY_DIRS
            ${hwloc_targ_BINARY_DIR}/Release;${hwloc_targ_BINARY_DIR}/Debug)
    else()
        include(FetchContent)
        message(
            STATUS
                "Will fetch hwloc from ${UMF_HWLOC_REPO} (tag: ${UMF_HWLOC_TAG})"
        )

        FetchContent_Declare(
            hwloc_targ
            GIT_REPOSITORY ${UMF_HWLOC_REPO}
            GIT_TAG ${UMF_HWLOC_TAG})
        FetchContent_MakeAvailable(hwloc_targ)

        add_custom_command(
            COMMAND ./autogen.sh
            WORKING_DIRECTORY ${hwloc_targ_SOURCE_DIR}
            OUTPUT ${hwloc_targ_SOURCE_DIR}/configure)
        add_custom_command(
            COMMAND
                ./configure --prefix=${hwloc_targ_BINARY_DIR}
                --enable-static=yes --enable-shared=no --disable-libxml2
                --disable-pci --disable-levelzero --disable-opencl
                --disable-cuda --disable-nvml --disable-libudev --disable-rsmi
                CFLAGS=-fPIC CXXFLAGS=-fPIC
            WORKING_DIRECTORY ${hwloc_targ_SOURCE_DIR}
            OUTPUT ${hwloc_targ_SOURCE_DIR}/Makefile
            DEPENDS ${hwloc_targ_SOURCE_DIR}/configure)
        add_custom_command(
            COMMAND make
            WORKING_DIRECTORY ${hwloc_targ_SOURCE_DIR}
            OUTPUT ${hwloc_targ_SOURCE_DIR}/lib/libhwloc.la
            DEPENDS ${hwloc_targ_SOURCE_DIR}/Makefile)
        add_custom_command(
            COMMAND make install
            WORKING_DIRECTORY ${hwloc_targ_SOURCE_DIR}
            OUTPUT ${hwloc_targ_BINARY_DIR}/lib/libhwloc.a
            DEPENDS ${hwloc_targ_SOURCE_DIR}/lib/libhwloc.la)

        add_custom_target(hwloc_prod
                          DEPENDS ${hwloc_targ_BINARY_DIR}/lib/libhwloc.a)
        add_library(hwloc INTERFACE)
        target_link_libraries(hwloc
                              INTERFACE ${hwloc_targ_BINARY_DIR}/lib/libhwloc.a)
        add_dependencies(hwloc hwloc_prod)

        set(LIBHWLOC_LIBRARY_DIRS ${hwloc_targ_BINARY_DIR}/lib)
        set(LIBHWLOC_INCLUDE_DIRS ${hwloc_targ_BINARY_DIR}/include)
        set(LIBHWLOC_LIBRARIES ${hwloc_targ_BINARY_DIR}/lib/libhwloc.a)
    endif()

    message(STATUS "    LIBHWLOC_LIBRARIES = ${LIBHWLOC_LIBRARIES}")
    message(STATUS "    LIBHWLOC_INCLUDE_DIRS = ${LIBHWLOC_INCLUDE_DIRS}")
    message(STATUS "    LIBHWLOC_LIBRARY_DIRS = ${LIBHWLOC_LIBRARY_DIRS}")
endif()

if(hwloc_targ_SOURCE_DIR)
    # apply security patch for HWLOC
    execute_process(
        COMMAND git apply ${PROJECT_SOURCE_DIR}/cmake/fix_coverity_issues.patch
        WORKING_DIRECTORY ${hwloc_targ_SOURCE_DIR}
        OUTPUT_VARIABLE UMF_HWLOC_PATCH_OUTPUT
        ERROR_VARIABLE UMF_HWLOC_PATCH_ERROR)

    if(UMF_HWLOC_PATCH_OUTPUT)
        message(STATUS "HWLOC patch command output:\n${UMF_HWLOC_PATCH_OUTPUT}")
    endif()
    if(UMF_HWLOC_PATCH_ERROR)
        message(WARNING "HWLOC patch command output:\n${UMF_HWLOC_PATCH_ERROR}")
    endif()
endif()

# Fetch L0 loader only if needed i.e.: if building L0 provider is ON and L0
# headers are not provided by the user (via setting UMF_LEVEL_ZERO_INCLUDE_DIR).
if(UMF_BUILD_LEVEL_ZERO_PROVIDER AND (NOT UMF_LEVEL_ZERO_INCLUDE_DIR))
    include(FetchContent)

    set(LEVEL_ZERO_LOADER_REPO "https://github.com/oneapi-src/level-zero.git")
    set(LEVEL_ZERO_LOADER_TAG v1.19.2)

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

# This build type check is not possible on Windows when CMAKE_BUILD_TYPE is not
# set, because in this case the build type is determined after a CMake
# configuration is done (at the build time)
if(NOT WINDOWS)
    set(KNOWN_BUILD_TYPES Release Debug RelWithDebInfo MinSizeRel)
    string(REPLACE ";" " " KNOWN_BUILD_TYPES_STR "${KNOWN_BUILD_TYPES}")

    if(NOT CMAKE_BUILD_TYPE)
        message(
            STATUS
                "No build type selected (CMAKE_BUILD_TYPE), defaulting to Release"
        )
        set(CMAKE_BUILD_TYPE "Release")
    else()
        message(STATUS "CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
        if(NOT CMAKE_BUILD_TYPE IN_LIST KNOWN_BUILD_TYPES)
            message(
                WARNING
                    "Unusual build type was set (${CMAKE_BUILD_TYPE}), please make sure it is a correct one. "
                    "The following ones are supported by default: ${KNOWN_BUILD_TYPES_STR}."
            )
        endif()
    endif()

    set(CMAKE_BUILD_TYPE
        "${CMAKE_BUILD_TYPE}"
        CACHE
            STRING
            "Choose the type of build, options are: ${KNOWN_BUILD_TYPES_STR} ..."
            FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS ${KNOWN_BUILD_TYPES})
endif()

# For using the options listed in the OPTIONS_REQUIRING_CXX variable a C++17
# compiler is required. Moreover, if these options are not set, CMake will set
# up a strict C build, without C++ support.
set(OPTIONS_REQUIRING_CXX "UMF_BUILD_TESTS" "UMF_BUILD_LIBUMF_POOL_DISJOINT"
                          "UMF_BUILD_BENCHMARKS_MT" "UMF_BUILD_BENCHMARKS")
foreach(option_name ${OPTIONS_REQUIRING_CXX})
    if(${option_name})
        enable_language(CXX)
        set(CMAKE_CXX_STANDARD 17)
        set(CMAKE_CXX_STANDARD_REQUIRED YES)
        break()
    endif()
endforeach()

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_UMF_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
if(CMAKE_GENERATOR MATCHES "Visual Studio" OR CMAKE_GENERATOR MATCHES
                                              "Ninja Multi-Config")
    set(CMAKE_UMF_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/$<CONFIG>)
endif()

# Sanitizer flags
if(UMF_USE_ASAN)
    add_sanitizer_flag(address)
endif()
if(UMF_USE_UBSAN)
    add_sanitizer_flag(undefined)
endif()
if(UMF_USE_TSAN)
    add_sanitizer_flag(thread)
endif()
if(UMF_USE_MSAN)
    message(WARNING "MemorySanitizer requires instrumented libraries to "
                    "prevent reporting false-positives")
    add_sanitizer_flag(memory)
endif()
# Fuzzer instrumentation for the whole library
if(UMF_BUILD_FUZZTESTS
   AND CMAKE_CXX_COMPILER_ID MATCHES "Clang"
   AND LINUX)
    add_compile_options("-fsanitize=fuzzer-no-link")
    add_link_options("-fsanitize=fuzzer-no-link")
endif()

# A header-only lib to specify include directories in transitive dependencies
add_library(umf_headers INTERFACE)

# Alias target to support FetchContent.
add_library(${PROJECT_NAME}::headers ALIAS umf_headers)
target_include_directories(
    umf_headers INTERFACE $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
                          $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

if(WINDOWS)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    # set PATH to DLLs on Windows
    set(DLL_PATH_LIST
        "${DLL_PATH_LIST};PATH=path_list_append:${PROJECT_BINARY_DIR}/bin/$<CONFIG>"
    )
    # add path to the proxy lib DLL
    set(DLL_PATH_LIST
        "${DLL_PATH_LIST};PATH=path_list_append:${PROJECT_BINARY_DIR}/src/proxy_lib"
    )
    # MSVC implicitly adds $<CONFIG> to the output path
    set(DLL_PATH_LIST
        "${DLL_PATH_LIST};PATH=path_list_append:${PROJECT_BINARY_DIR}/src/proxy_lib/$<CONFIG>"
    )
endif()

pkg_check_modules(TBB tbb)
if(NOT TBB_FOUND)
    find_package(TBB OPTIONAL_COMPONENTS tbb)
endif()
if(TBB_FOUND OR TBB_LIBRARY_DIRS)
    # add PATH to DLL on Windows
    set(DLL_PATH_LIST "${DLL_PATH_LIST};PATH=path_list_append:${TBB_DLL_DIRS}")
    set(UMF_POOL_SCALABLE_ENABLED TRUE)
else()
    message(
        STATUS
            "Disabling tests and benchmarks that use the Scalable Pool because the TBB they require was not found."
    )
    set(UMF_POOL_SCALABLE_ENABLED FALSE)
endif()

if(WINDOWS)
    # TODO: enable the proxy library in the Debug build on Windows
    #
    # In MSVC builds, there is no way to determine the actual build type during
    # the CMake configuration step. Therefore, this message is printed in all
    # MSVC builds.
    if(UMF_LINK_HWLOC_STATICALLY)
        message(
            STATUS
                "The proxy library will be disabled - static linkage with hwloc is not supported yet"
        )
    else()
        message(
            STATUS
                "The proxy library will be built, however it is supported only in the Release build on Windows"
        )
    endif()
endif()

# set UMF_PROXY_LIB_ENABLED
if(UMF_DISABLE_HWLOC)
    message(STATUS "Disabling the proxy library, because HWLOC is disabled")
elseif(NOT UMF_BUILD_SHARED_LIBRARY)
    # TODO enable this scenario
    message(
        STATUS
            "Disabling the proxy library, because UMF is built as static library"
    )
elseif(UMF_PROXY_LIB_BASED_ON_POOL STREQUAL SCALABLE)
    if(UMF_POOL_SCALABLE_ENABLED)
        set(UMF_PROXY_LIB_ENABLED ON)
        set(PROXY_LIB_USES_SCALABLE_POOL ON)
        set(PROXY_LIBS umf)
    else()
        message(
            STATUS
                "Disabling the proxy library, because UMF_PROXY_LIB_BASED_ON_POOL==SCALABLE but TBB was not found"
        )
    endif()
elseif(UMF_PROXY_LIB_BASED_ON_POOL STREQUAL JEMALLOC)
    if(UMF_POOL_JEMALLOC_ENABLED)
        set(UMF_PROXY_LIB_ENABLED ON)
        set(PROXY_LIB_USES_JEMALLOC_POOL ON)
        set(PROXY_LIBS umf)
    else()
        message(
            STATUS
                "Disabling the proxy library, because UMF_PROXY_LIB_BASED_ON_POOL==JEMALLOC but the jemalloc pool is disabled"
        )
    endif()
else()
    message(
        FATAL_ERROR
            "Proxy library: pool manager not chosen or set to a non-supported one (see UMF_PROXY_LIB_BASED_ON_POOL)"
    )
endif()

if((UMF_BUILD_GPU_TESTS OR UMF_BUILD_GPU_EXAMPLES) AND UMF_BUILD_CUDA_PROVIDER)
    find_package(CUDA REQUIRED cuda)
    if(CUDA_LIBRARIES)
        set(UMF_CUDA_ENABLED TRUE)
    else()
        message(
            STATUS "Disabling tests and examples that use the CUDA provider "
                   "because the CUDA libraries they require were not found.")
    endif()
    # TODO do the same for ze_loader
endif()

add_subdirectory(src)

if(UMF_BUILD_TESTS)
    add_subdirectory(test)
endif()

if(UMF_BUILD_BENCHMARKS)
    add_subdirectory(benchmark)
endif()

if(UMF_BUILD_EXAMPLES AND NOT UMF_DISABLE_HWLOC)
    add_subdirectory(examples)
endif()

if(UMF_FORMAT_CODE_STYLE)
    find_program(CLANG_FORMAT NAMES clang-format-15 clang-format-15.0
                                    clang-format)
    find_program(CMAKE_FORMAT NAMES cmake-format)
    find_program(BLACK NAMES black)

    set(CLANG_FORMAT_REQUIRED "15.0")
    set(CMAKE_FORMAT_REQUIRED "0.6")

    if(NOT CLANG_FORMAT
       AND NOT CMAKE_FORMAT
       AND NOT BLACK)
        message(
            FATAL_ERROR
                "UMF_FORMAT_CODE_STYLE=ON, but neither clang-format (required version: "
                "${CLANG_FORMAT_REQUIRED}), nor cmake-format (required version: "
                "${CMAKE_FORMAT_REQUIRED}), nor black was found.")
    endif()

    if(CLANG_FORMAT)
        get_program_version_major_minor(${CLANG_FORMAT} CLANG_FORMAT_VERSION)
        message(STATUS "Found clang-format: ${CLANG_FORMAT} "
                       "(version: ${CLANG_FORMAT_VERSION})")

        # Check if clang-format (in correct version) is available for code
        # formatting.
        if(NOT (CLANG_FORMAT_VERSION VERSION_EQUAL CLANG_FORMAT_REQUIRED))
            message(FATAL_ERROR "Required clang-format version is "
                                "${CLANG_FORMAT_REQUIRED}")
        endif()

        # Obtain files for clang-format check
        set(format_clang_glob)
        foreach(
            DIR IN
            ITEMS benchmark
                  examples
                  include
                  src
                  test)
            list(
                APPEND
                format_clang_glob
                "${DIR}/*.h"
                "${DIR}/*.hpp"
                "${DIR}/*.c"
                "${DIR}/*.cpp"
                "${DIR}/**/*.h"
                "${DIR}/**/*.hpp"
                "${DIR}/**/*.c"
                "${DIR}/**/*.cpp")
        endforeach()
        file(GLOB_RECURSE format_list ${format_clang_glob})

        message(
            STATUS
                "Adding 'clang-format-check' and 'clang-format-apply' targets")

        add_custom_target(
            clang-format-check
            COMMAND ${CLANG_FORMAT} --style=file --dry-run -Werror
                    ${format_list}
            COMMENT "Check files formatting using clang-format")

        add_custom_target(
            clang-format-apply
            COMMAND ${CLANG_FORMAT} --style=file -i ${format_list}
            COMMENT "Format files using clang-format")
    endif()

    if(CMAKE_FORMAT)
        get_program_version_major_minor(${CMAKE_FORMAT} CMAKE_FORMAT_VERSION)
        message(STATUS "Found cmake-format: ${CMAKE_FORMAT} "
                       "(version: ${CMAKE_FORMAT_VERSION})")

        # Check if cmake-format (in correct version) is available for cmake
        # files formatting.
        if(NOT (CMAKE_FORMAT_VERSION VERSION_EQUAL CMAKE_FORMAT_REQUIRED))
            message(FATAL_ERROR "Required cmake-format version is"
                                "${CMAKE_FORMAT_REQUIRED}")
        endif()

        # Obtain files for cmake-format check
        set(format_cmake_glob)
        foreach(
            DIR IN
            ITEMS cmake
                  benchmark
                  examples
                  include
                  src
                  test)
            list(
                APPEND
                format_cmake_glob
                "${DIR}/CMakeLists.txt"
                "${DIR}/*.cmake"
                "${DIR}/**/CMakeLists.txt"
                "${DIR}/**/*.cmake")
        endforeach()
        file(GLOB_RECURSE format_cmake_list ${format_cmake_glob})
        list(APPEND format_cmake_list "${PROJECT_SOURCE_DIR}/CMakeLists.txt")

        message(
            STATUS
                "Adding 'cmake-format-check' and 'cmake-format-apply' targets")

        add_custom_target(
            cmake-format-check
            COMMAND ${CMAKE_FORMAT} --check ${format_cmake_list}
            COMMENT "Check CMake files formatting using cmake-format")

        add_custom_target(
            cmake-format-apply
            COMMAND ${CMAKE_FORMAT} --in-place ${format_cmake_list}
            COMMENT "Format Cmake files using cmake-format")
    endif()

    if(BLACK)
        # black should maintain backward compatibility, we don't have to require
        # a specific version
        get_program_version_major_minor(${BLACK} BLACK_VERSION)
        message(STATUS "Found black: ${BLACK} (version: ${BLACK_VERSION})")

        message(
            STATUS
                "Adding 'black-format-check' and 'black-format-apply' targets")

        add_custom_target(
            black-format-check
            COMMAND ${BLACK} --check --verbose ${UMF_CMAKE_SOURCE_DIR}
            COMMENT "Check Python files formatting using black formatter")

        add_custom_target(
            black-format-apply
            COMMAND ${BLACK} ${UMF_CMAKE_SOURCE_DIR}
            COMMENT "Format Python files using black formatter")
    endif()

    # Add a convenience target for running all tools at once - available only if
    # all are found.
    if(CLANG_FORMAT
       AND CMAKE_FORMAT
       AND BLACK)
        add_custom_target(
            format-check
            COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target
                    clang-format-check
            COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target
                    cmake-format-check
            COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target
                    black-format-check
            COMMENT "Running all formatting checks")

        add_custom_target(
            format-apply
            COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target
                    clang-format-apply
            COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target
                    cmake-format-apply
            COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target
                    black-format-apply
            COMMENT "Format C/C++, CMake, and Python files")
        message(
            STATUS
                "  Adding convenience targets 'format-check' and 'format-apply'."
        )
    else()
        message(
            STATUS
                "  Convenience targets 'format-check' and 'format-apply' are "
                "not available. Use commands specific for found tools (see the log above)."
        )
    endif()
endif()

# --------------------------------------------------------------------------- #
# Configure make install/uninstall and packages
# --------------------------------------------------------------------------- #
install(FILES ${PROJECT_SOURCE_DIR}/LICENSE.TXT
        DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/doc/${PROJECT_NAME}/")
install(
    FILES ${PROJECT_SOURCE_DIR}/licensing/third-party-programs.txt
    DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/doc/${PROJECT_NAME}/licensing/")

install(DIRECTORY examples DESTINATION "${CMAKE_INSTALL_DOCDIR}")

# Add the include directory and the headers target to the install.
install(DIRECTORY "${PROJECT_SOURCE_DIR}/include/"
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(TARGETS umf_headers EXPORT ${PROJECT_NAME}-targets)

# Add the list of installed targets to the install. This includes the namespace
# which all installed targets will be prefixed with, e.g. for the headers target
# users will depend on ${PROJECT_NAME}::headers.
install(
    EXPORT ${PROJECT_NAME}-targets
    FILE ${PROJECT_NAME}-targets.cmake
    NAMESPACE ${PROJECT_NAME}::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})

# Configure the package versions file for use in find_package when installed.
write_basic_package_version_file(
    ${PROJECT_BINARY_DIR}/cmake/${PROJECT_NAME}-config-version.cmake
    COMPATIBILITY SameMajorVersion)

# Configure the package file that is searched for by find_package when
# installed.
configure_package_config_file(
    ${PROJECT_SOURCE_DIR}/cmake/${PROJECT_NAME}-config.cmake.in
    ${PROJECT_BINARY_DIR}/cmake/${PROJECT_NAME}-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})

# Add the package files to the install.
install(FILES ${PROJECT_BINARY_DIR}/cmake/${PROJECT_NAME}-config.cmake
              ${PROJECT_BINARY_DIR}/cmake/${PROJECT_NAME}-config-version.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})

# Configure uninstall commands
configure_file("${PROJECT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
               "${PROJECT_BINARY_DIR}/cmake_uninstall.cmake" IMMEDIATE @ONLY)

add_custom_target(uninstall COMMAND ${CMAKE_COMMAND} -P
                                    ${PROJECT_BINARY_DIR}/cmake_uninstall.cmake)
