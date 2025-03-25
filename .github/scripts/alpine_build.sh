#!/bin/bash
# Copyright (C) 2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# alpine_build.sh - Script for building UMF on Alpine image

set -e

UMF_BUILD_TYPE=$1
WORKDIR=$2

sudo chown $USER $WORKDIR
cd unified-memory-framework

cmake -B build -DCMAKE_BUILD_TYPE=$UMF_BUILD_TYPE -DUMF_BUILD_TESTS=ON -DUMF_BUILD_EXAMPLES=ON
cmake --build build
