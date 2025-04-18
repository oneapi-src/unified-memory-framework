# Copyright (C) 2022-2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14.0 FATAL_ERROR)
# needed when UMF is used as an external project
set(UMF_CMAKE_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

list(APPEND CMAKE_MODULE_PATH "${UMF_CMAKE_SOURCE_DIR}/cmake")
# Use full path of the helpers module (to omit potential conflicts with others)
include(${UMF_CMAKE_SOURCE_DIR}/cmake/helpers.cmake)

# --------------------------------------------------------------------------- #
# Set UMF version variables, define project, and add basic modules
# --------------------------------------------------------------------------- #

# We use semver aligned version, set via git tags. We parse git output to
# establish the version of UMF to be used in CMake, Win dll's, and within the
# code (e.g. in logger). We have 3-component releases (e.g. 1.5.1) plus release
# candidates and git info. Function below sets all variables related to version.
set_version_variables()
message(STATUS "UMF version: ${UMF_VERSION}")

# version we set in CMake is abbreviated just to major.minor.patch
project(
    umf
    VERSION ${UMF_CMAKE_VERSION}
    LANGUAGES C)
if(UMF_CMAKE_VERSION VERSION_EQUAL "0.0.0")
    message(
        WARNING
            "UMF version is set to 0.0.0, which most likely is not expected! "
            "Please checkout the git tags to get a proper version.")
endif()

if(PROJECT_VERSION_PATCH GREATER 0)
    # set extra variable for Windows dll metadata
    set(UMF_VERSION_BUGFIX 1)
endif()

include(CTest)
include(CMakePackageConfigHelpers)
include(GNUInstallDirs)
include(FetchContent)
find_package(PkgConfig)

# --------------------------------------------------------------------------- #
# Set UMF build options (and CACHE variables)
# --------------------------------------------------------------------------- #

# Define a list to store the names of all options
set(UMF_OPTIONS_LIST "")
list(APPEND UMF_OPTIONS_LIST CMAKE_BUILD_TYPE)

# Define a macro to wrap the option() command and track the options
macro(umf_option)
    list(APPEND UMF_OPTIONS_LIST ${ARGV0})
    option(${ARGV})
endmacro()

# All CMake options have to be explicitly set in the build_umfd target's
# configuration command
umf_option(UMF_BUILD_SHARED_LIBRARY "Build UMF as shared library" OFF)
umf_option(UMF_BUILD_LEVEL_ZERO_PROVIDER "Build Level Zero memory provider" ON)
umf_option(UMF_BUILD_CUDA_PROVIDER "Build CUDA memory provider" ON)
umf_option(UMF_BUILD_LIBUMF_POOL_JEMALLOC
           "Build the libumf_pool_jemalloc static library" OFF)
umf_option(UMF_BUILD_TESTS "Build UMF tests" ON)
umf_option(UMF_BUILD_GPU_TESTS "Build UMF GPU tests" OFF)
umf_option(UMF_BUILD_BENCHMARKS "Build UMF benchmarks" OFF)
umf_option(UMF_BUILD_BENCHMARKS_MT "Build UMF multithreaded benchmarks" OFF)
umf_option(UMF_BUILD_EXAMPLES "Build UMF examples" ON)
umf_option(UMF_BUILD_GPU_EXAMPLES "Build UMF GPU examples" OFF)
umf_option(UMF_BUILD_FUZZTESTS "Build UMF fuzz tests" OFF)
umf_option(
    UMF_LINK_HWLOC_STATICALLY
    "Link UMF with HWLOC library statically (proxy library will be disabled on Windows+Debug build)"
    OFF)
set(UMF_HWLOC_NAME
    "hwloc"
    CACHE STRING "Custom name for hwloc library w/o extension")
list(APPEND UMF_OPTIONS_LIST UMF_HWLOC_NAME)
set(UMF_INSTALL_RPATH
    ""
    CACHE
        STRING
        "Set the runtime search path to the directory with dependencies (e.g. hwloc)"
)

umf_option(UMF_USE_DEBUG_POSTFIX "Add a 'd' postfix to Windows debug libraries"
           OFF)
umf_option(UMF_DEVELOPER_MODE "Enable additional developer checks" OFF)
umf_option(
    UMF_FORMAT_CODE_STYLE
    "Add clang, cmake, and black -format-check and -format-apply targets" OFF)
# Only a part of skips is treated as a failure now. TODO: extend to all tests
umf_option(UMF_TESTS_FAIL_ON_SKIP "Treat skips in tests as fail" OFF)
umf_option(UMF_USE_ASAN "Enable AddressSanitizer checks" OFF)
umf_option(UMF_USE_UBSAN "Enable UndefinedBehaviorSanitizer checks" OFF)
umf_option(UMF_USE_TSAN "Enable ThreadSanitizer checks" OFF)
umf_option(UMF_USE_MSAN "Enable MemorySanitizer checks" OFF)
umf_option(UMF_USE_VALGRIND "Enable Valgrind instrumentation" OFF)
umf_option(UMF_USE_COVERAGE "Build with coverage enabled (Linux only)" OFF)

# set UMF_PROXY_LIB_BASED_ON_POOL to one of: SCALABLE or JEMALLOC
set(KNOWN_PROXY_LIB_POOLS SCALABLE JEMALLOC)
set(UMF_PROXY_LIB_BASED_ON_POOL
    SCALABLE
    CACHE STRING
          "A UMF pool the proxy library is based on (SCALABLE or JEMALLOC)")
set_property(CACHE UMF_PROXY_LIB_BASED_ON_POOL
             PROPERTY STRINGS ${KNOWN_PROXY_LIB_POOLS})
list(APPEND UMF_OPTIONS_LIST UMF_PROXY_LIB_BASED_ON_POOL)

# --------------------------------------------------------------------------- #
# Setup required variables, definitions; fetch dependencies; include
# sub_directories based on build options; set flags; etc.
# --------------------------------------------------------------------------- #
message(STATUS "CMAKE_GENERATOR: ${CMAKE_GENERATOR}")

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

if(UMF_DEVELOPER_MODE)
    set(UMF_COMMON_COMPILE_DEFINITIONS ${UMF_COMMON_COMPILE_DEFINITIONS}
                                       UMF_DEVELOPER_MODE=1)
endif()

message(STATUS "CMAKE_PREFIX_PATH=${CMAKE_PREFIX_PATH}")

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
        # loaded after program startup (e.g. using dlopen). --disable-doc -
        # Disable building and installing the documentation.
        COMMAND
            ./configure --prefix=${jemalloc_targ_BINARY_DIR}
            --with-jemalloc-prefix=je_ --disable-cxx --disable-initial-exec-tls
            --disable-doc CFLAGS=-fPIC
        WORKING_DIRECTORY ${jemalloc_targ_SOURCE_DIR}
        OUTPUT ${jemalloc_targ_SOURCE_DIR}/Makefile
        DEPENDS ${jemalloc_targ_SOURCE_DIR}/configure)

    if(NOT UMF_QEMU_BUILD)
        set(MAKE_ARGUMENTS "-j$(nproc)")
    endif()

    add_custom_command(
        COMMAND make ${MAKE_ARGUMENTS}
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
    if(WINDOWS)
        message(STATUS "    JEMALLOC_DLL_DIRS = ${JEMALLOC_DLL_DIRS}")
    endif()
else()
    set(UMF_POOL_JEMALLOC_ENABLED FALSE)
    message(
        STATUS
            "Disabling the Jemalloc Pool and tests and benchmarks that use it because jemalloc was not built/found."
    )
endif()

if(NOT UMF_LINK_HWLOC_STATICALLY)
    pkg_check_modules(LIBHWLOC hwloc>=2.3.0)
    if(NOT LIBHWLOC_FOUND)
        find_package(LIBHWLOC 2.3.0 COMPONENTS hwloc)
        if(LIBHWLOC_LIBRARIES)
            set(LIBHWLOC_AVAILABLE TRUE)
        endif()
    endif()

    if(LIBHWLOC_AVAILABLE OR LIBHWLOC_FOUND)
        # add PATH to DLL on Windows
        set(DLL_PATH_LIST
            "${DLL_PATH_LIST};PATH=path_list_append:${LIBHWLOC_DLL_DIRS}")
    else()
        set(UMF_LINK_HWLOC_STATICALLY ON)
    endif()
endif()

if(UMF_LINK_HWLOC_STATICALLY)
    if(NOT DEFINED UMF_HWLOC_REPO)
        set(UMF_HWLOC_REPO "https://github.com/open-mpi/hwloc.git")
    endif()
    if(NOT DEFINED UMF_HWLOC_TAG)
        set(UMF_HWLOC_TAG hwloc-2.10.0)
    endif()

    message(
        STATUS "Will fetch hwloc from ${UMF_HWLOC_REPO} (tag: ${UMF_HWLOC_TAG})"
    )

    if(WINDOWS)
        set(HWLOC_ENABLE_TESTING OFF)
        set(HWLOC_SKIP_LSTOPO ON)
        set(HWLOC_SKIP_TOOLS ON)
        set(HWLOC_SKIP_INCLUDES ON)

        FetchContent_Declare(
            hwloc_targ
            GIT_REPOSITORY ${UMF_HWLOC_REPO}
            GIT_TAG ${UMF_HWLOC_TAG}
            SOURCE_SUBDIR contrib/windows-cmake/)
        FetchContent_MakeAvailable(hwloc_targ)

        set(HWLOC_LIB_PATH "")
        if(CMAKE_GENERATOR STREQUAL "NMake Makefiles")
            set(HWLOC_LIB_PATH "${hwloc_targ_BINARY_DIR}/hwloc.lib")
        else()
            set(HWLOC_LIB_PATH "${hwloc_targ_BINARY_DIR}/lib/hwloc.lib")
        endif()

        get_filename_component(LIBHWLOC_LIBRARY_DIRS ${HWLOC_LIB_PATH}
                               DIRECTORY)
        set(LIBHWLOC_LIBRARIES ${HWLOC_LIB_PATH})
        set(LIBHWLOC_INCLUDE_DIRS ${hwloc_targ_BINARY_DIR}/include)
    else() # not Windows
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
endif() # UMF_LINK_HWLOC_STATICALLY

message(STATUS "    LIBHWLOC_LIBRARIES = ${LIBHWLOC_LIBRARIES}")
message(STATUS "    LIBHWLOC_INCLUDE_DIRS = ${LIBHWLOC_INCLUDE_DIRS}")
message(STATUS "    LIBHWLOC_LIBRARY_DIRS = ${LIBHWLOC_LIBRARY_DIRS}")
message(STATUS "    LIBHWLOC_API_VERSION = ${LIBHWLOC_API_VERSION}")
if(WINDOWS)
    message(STATUS "    LIBHWLOC_DLL_DIRS = ${LIBHWLOC_DLL_DIRS}")
endif()

if(hwloc_targ_SOURCE_DIR)
    # Apply security patch for HWLOC
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
    set(LEVEL_ZERO_LOADER_REPO "https://github.com/oneapi-src/level-zero.git")
    set(LEVEL_ZERO_LOADER_TAG v1.20.2)

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
    message(STATUS "CUDA_INCLUDE_DIRS = ${CUDA_INCLUDE_DIRS}")
elseif(UMF_BUILD_CUDA_PROVIDER)
    # Only header is needed to build UMF
    set(CUDA_INCLUDE_DIRS ${UMF_CUDA_INCLUDE_DIR})
    message(STATUS "CUDA_INCLUDE_DIRS = ${CUDA_INCLUDE_DIRS}")
endif()

# Build the umfd target in a separate directory with Debug configuration
if(WINDOWS AND UMF_USE_DEBUG_POSTFIX)
    # The build_umfd target's configuration command requires to have
    # CMAKE_PREFIX_PATH with semicolons escaped
    string(JOIN "\;" UMFD_CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH})
    add_custom_target(
        build_umfd ALL
        COMMAND
            ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" -S ${UMF_CMAKE_SOURCE_DIR}
            -B ${CMAKE_BINARY_DIR}/umfd_build -DCMAKE_BUILD_TYPE=Debug
            -DCMAKE_DEBUG_POSTFIX=d
            -DCMAKE_PREFIX_PATH="${UMFD_CMAKE_PREFIX_PATH}"
            -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
            -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
            -DUMF_USE_DEBUG_POSTFIX=OFF
            -DUMF_BUILD_SHARED_LIBRARY=${UMF_BUILD_SHARED_LIBRARY}
            -DUMF_BUILD_LEVEL_ZERO_PROVIDER=${UMF_BUILD_LEVEL_ZERO_PROVIDER}
            -DUMF_BUILD_CUDA_PROVIDER=${UMF_BUILD_CUDA_PROVIDER}
            -DUMF_BUILD_LIBUMF_POOL_JEMALLOC=${UMF_BUILD_LIBUMF_POOL_JEMALLOC}
            -DUMF_BUILD_TESTS=OFF -DUMF_BUILD_GPU_TESTS=OFF
            -DUMF_BUILD_BENCHMARKS=OFF -DUMF_BUILD_BENCHMARKS_MT=OFF
            -DUMF_BUILD_EXAMPLES=OFF -DUMF_BUILD_GPU_EXAMPLES=OFF
            -DUMF_BUILD_FUZZTESTS=OFF
            -DUMF_LINK_HWLOC_STATICALLY=${UMF_LINK_HWLOC_STATICALLY}
            -DUMF_HWLOC_NAME=${UMF_HWLOC_NAME}
            -DUMF_INSTALL_RPATH=${UMF_INSTALL_RPATH} -DUMF_DEVELOPER_MODE=OFF
            -DUMF_FORMAT_CODE_STYLE=OFF -DUMF_TESTS_FAIL_ON_SKIP=OFF
            -DUMF_USE_ASAN=OFF -DUMF_USE_UBSAN=OFF -DUMF_USE_TSAN=OFF
            -DUMF_USE_MSAN=OFF -DUMF_USE_VALGRIND=OFF -DUMF_USE_COVERAGE=OFF
            -DUMF_PROXY_LIB_BASED_ON_POOL=${UMF_PROXY_LIB_BASED_ON_POOL}
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/umfd_build --target
                umf --config Debug
        COMMENT
            "Configuring and building umfd.dll in a separate directory with Debug configuration"
    )

    # Copy built UMF libraries to the main binary directory and remove
    # umfd_build
    if(CMAKE_CONFIGURATION_TYPES)
        # Multi-config generator (e.g., Visual Studio)
        set(UMFD_DLL_SRC "${CMAKE_BINARY_DIR}/umfd_build/bin/Debug/umfd.dll")
        set(UMFD_LIB_SRC "${CMAKE_BINARY_DIR}/umfd_build/lib/Debug/umfd.lib")
        set(UMFD_DLL "${CMAKE_BINARY_DIR}/bin/$<CONFIG>/umfd.dll")
        set(UMFD_LIB "${CMAKE_BINARY_DIR}/lib/$<CONFIG>/umfd.lib")
    else()
        # Single-config generator (e.g., Ninja)
        set(UMFD_DLL_SRC "${CMAKE_BINARY_DIR}/umfd_build/bin/umfd.dll")
        set(UMFD_LIB_SRC "${CMAKE_BINARY_DIR}/umfd_build/lib/umfd.lib")
        set(UMFD_DLL "${CMAKE_BINARY_DIR}/bin/umfd.dll")
        set(UMFD_LIB "${CMAKE_BINARY_DIR}/lib/umfd.lib")
    endif()

    if(UMF_BUILD_SHARED_LIBRARY)
        add_custom_command(
            TARGET build_umfd
            COMMAND ${CMAKE_COMMAND} -E copy_if_different ${UMFD_DLL_SRC}
                    ${UMFD_DLL}
            COMMENT "Copying umfd.dll to the main binary directory")
    endif()
    add_custom_command(
        TARGET build_umfd
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${UMFD_LIB_SRC}
                ${UMFD_LIB}
        COMMAND ${CMAKE_COMMAND} -E remove_directory
                ${CMAKE_BINARY_DIR}/umfd_build DEPENDS ${UMFD_DLL}
        COMMENT "Copying umfd.lib to the main library directory")
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
set(OPTIONS_REQUIRING_CXX "UMF_BUILD_TESTS" "UMF_BUILD_BENCHMARKS_MT"
                          "UMF_BUILD_BENCHMARKS")
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
if(NOT UMF_BUILD_SHARED_LIBRARY)
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

if(UMF_BUILD_EXAMPLES)
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
            COMMENT "Format CMake files using cmake-format")
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

find_package(Python3 3.8)
if(Python3_FOUND)
    message(STATUS "Adding 'docs' target for creating a documentation.")
    add_custom_target(
        docs
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMAND UMF_VERSION=${UMF_CMAKE_VERSION} ${Python3_EXECUTABLE}
                ${UMF_CMAKE_SOURCE_DIR}/docs/generate_docs.py
        COMMENT "Generate HTML documentation using Doxygen")
endif()

# --------------------------------------------------------------------------- #
# Configure make install/uninstall and packages
# --------------------------------------------------------------------------- #
# Install the umfd library files as part of the umfd component
if(WINDOWS AND UMF_USE_DEBUG_POSTFIX)
    if(UMF_BUILD_SHARED_LIBRARY)
        install(
            FILES ${UMFD_DLL}
            DESTINATION ${CMAKE_INSTALL_BINDIR}
            COMPONENT umfd)
    endif()
    install(
        FILES ${UMFD_LIB}
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
        COMPONENT umfd)
endif()

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
