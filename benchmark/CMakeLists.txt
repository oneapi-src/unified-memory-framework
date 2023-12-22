# Copyright (C) 2023 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	message(WARNING "The ubench SHOULD NOT be run in the Debug build type!")
endif()

if(UMF_BUILD_LIBUMF_POOL_DISJOINT)
	set(LIBS_OPTIONAL ${LIBS_OPTIONAL} disjoint_pool)
endif()

add_executable(ubench ubench.c)

add_dependencies(ubench
	umf
	${LIBS_OPTIONAL})

target_include_directories(ubench PRIVATE ${UMF_CMAKE_SOURCE_DIR}/include/)

target_link_libraries(ubench
	umf
	${LIBS_OPTIONAL}
	pthread
	m)

if (UMF_BUILD_LIBUMF_POOL_DISJOINT)
	target_compile_definitions(ubench PRIVATE UMF_BUILD_LIBUMF_POOL_DISJOINT=1)
endif()
