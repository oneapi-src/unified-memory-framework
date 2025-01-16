# Copyright (C) 2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

if(NOT VALGRIND_ROOT AND DEFINED ENV{VALGRIND_ROOT})
	set(VALGRIND_ROOT "$ENV{VALGRIND_ROOT}" CACHE PATH "Valgrind base directory location (optional, used for nonstandard installation paths)")
	mark_as_advanced(VALGRIND_ROOT)
endif()

# Search path for nonstandard locations
if(VALGRIND_ROOT)
	set(Valgrind_INCLUDE_PATH PATHS "${VALGRIND_ROOT}/include"  "${VALGRIND_ROOT}/valgrind/current/usr/include" NO_DEFAULT_PATH)
	set(Valgrind_BINARY_PATH PATHS "${VALGRIND_ROOT}/bin" NO_DEFAULT_PATH)
endif()

find_path(Valgrind_INCLUDE_DIR valgrind/memcheck.h HINTS ${Valgrind_INCLUDE_PATH})
find_program(Valgrind_EXECUTABLE NAMES valgrind PATH ${Valgrind_BINARY_PATH}) 

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Valgrind DEFAULT_MSG Valgrind_INCLUDE_DIR Valgrind_EXECUTABLE)

mark_as_advanced(Valgrind_INCLUDE_DIR Valgrind_EXECUTABLE)