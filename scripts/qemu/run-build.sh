#!/bin/bash
# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set -e

[ "$1" = "COVERAGE" ] && COVERAGE=ON || COVERAGE=OFF

# This is ${UMF_DIR}/scripts/qemu/run-build.sh file, so
UMF_DIR=$(dirname $0)/../..
cd $UMF_DIR
pwd

echo password | sudo -Sk apt-get update
echo password | sudo -Sk apt-get install -y git cmake gcc g++ pkg-config \
    numactl libnuma-dev hwloc libhwloc-dev libjemalloc-dev libtbb-dev valgrind lcov

mkdir build
cd build

cmake .. \
    -DCMAKE_BUILD_TYPE=Debug \
    -DUMF_BUILD_LEVEL_ZERO_PROVIDER=ON \
    -DUMF_BUILD_CUDA_PROVIDER=ON \
    -DUMF_FORMAT_CODE_STYLE=OFF \
    -DUMF_DEVELOPER_MODE=ON \
    -DUMF_BUILD_LIBUMF_POOL_DISJOINT=ON \
    -DUMF_BUILD_LIBUMF_POOL_JEMALLOC=ON \
    -DUMF_BUILD_EXAMPLES=ON \
    -DUMF_USE_COVERAGE=${COVERAGE} \
    -DUMF_TESTS_FAIL_ON_SKIP=ON

make -j $(nproc)
