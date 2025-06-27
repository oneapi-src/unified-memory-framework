# Copyright (C) 2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

pkg_check_modules(LIBUMF libumf)
if(NOT LIBUMF_FOUND)
    find_package(LIBUMF REQUIRED libumf)
endif()
