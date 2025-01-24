# Copyright (C) 2023-2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

if(UMF_BUILD_SHARED_LIBRARY)
    set(POOL_EXTRA_SRCS ${BA_SOURCES})
    set(POOL_EXTRA_LIBS $<BUILD_INTERFACE:umf_utils>)
endif()

set(POOL_COMPILE_DEFINITIONS ${UMF_COMMON_COMPILE_DEFINITIONS})
