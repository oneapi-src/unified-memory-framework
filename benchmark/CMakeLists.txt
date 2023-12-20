# Copyright (C) 2023 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	message(WARNING "The ubench SHOULD NOT be run in the Debug build type!")
endif()

add_executable(ubench ubench.c)
add_dependencies(ubench unified_memory_framework)
target_include_directories(ubench PRIVATE ${UMF_CMAKE_SOURCE_DIR}/include/)
target_link_libraries(ubench
	unified_memory_framework
	${LIBS_UMF_STATIC}
	m)
