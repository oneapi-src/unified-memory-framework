#!/bin/bash
# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set -x
set -e

repo=$1
branch=$2

echo password | sudo -Sk apt update
echo password | sudo -Sk apt install -y git cmake gcc g++ numactl libnuma-dev libhwloc-dev libjemalloc-dev libtbb-dev pkg-config valgrind hwloc

# Set ptrace value for IPC test
echo password | sudo bash -c "echo 0 > /proc/sys/kernel/yama/ptrace_scope"

numactl -H

git clone $repo umf
cd umf
git checkout $branch

mkdir build
cd build

cmake .. \
    -DCMAKE_BUILD_TYPE=Debug \
    -DUMF_BUILD_LEVEL_ZERO_PROVIDER=ON \
    -DUMF_FORMAT_CODE_STYLE=OFF \
    -DUMF_DEVELOPER_MODE=ON \
    -DUMF_BUILD_LIBUMF_POOL_DISJOINT=ON \
    -DUMF_BUILD_LIBUMF_POOL_JEMALLOC=ON \
    -DUMF_BUILD_EXAMPLES=ON

make -j $(nproc)
