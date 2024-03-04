# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

if(UMF_BUILD_OS_MEMORY_PROVIDER
        AND UMF_BUILD_LIBUMF_POOL_SCALABLE
        AND UMF_ENABLE_POOL_TRACKING)
   set(EXAMPLE_NAME umf_example_basic)
   add_umf_executable(NAME ${EXAMPLE_NAME}
                      SRCS basic/basic.c
                      LIBS umf
                           scalable_pool)
    target_include_directories(${EXAMPLE_NAME} PRIVATE
        ${UMF_CMAKE_SOURCE_DIR}/src/utils
        ${UMF_CMAKE_SOURCE_DIR}/include)

    add_test(NAME ${EXAMPLE_NAME}
             COMMAND ${EXAMPLE_NAME}
             WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

    set_tests_properties(${EXAMPLE_NAME} PROPERTIES LABELS "example")

    if(WINDOWS)
        # append PATH to DLLs
        set(DLL_PATH_LIST "PATH=path_list_append:../bin/$<CONFIG>")
        if(LIBHWLOC_DLL_DIRS)
            set(DLL_PATH_LIST "${DLL_PATH_LIST};PATH=path_list_append:${LIBHWLOC_DLL_DIRS}")
        endif()
        if(LIBTBB_DLL_DIRS)
            set(DLL_PATH_LIST "${DLL_PATH_LIST};PATH=path_list_append:${LIBTBB_DLL_DIRS}")
        endif()
        set_property(TEST ${EXAMPLE_NAME} PROPERTY ENVIRONMENT_MODIFICATION "${DLL_PATH_LIST}")
    endif()

    install(FILES basic/basic.c
            DESTINATION "${CMAKE_INSTALL_DOCDIR}/examples")

else()
    message(STATUS "Basic example requires UMF_BUILD_OS_MEMORY_PROVIDER,
                    UMF_BUILD_LIBUMF_POOL_SCALABLE and UMF_ENABLE_POOL_TRACKING
                    to be turned ON - skipping")
endif()
