#!/bin/bash
# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set -e

# Drop caches, restores free memory on NUMA nodes
echo password | sudo sync;
echo password | sudo sh -c "/usr/bin/echo 3 > /proc/sys/vm/drop_caches"
# Set ptrace value for IPC test
echo password | sudo bash -c "echo 0 > /proc/sys/kernel/yama/ptrace_scope"

numactl -H

cd umf/build
ctest --verbose

# run tests bound to a numa node
numactl -N 0 ctest --output-on-failure
numactl -N 1 ctest --output-on-failure

# run tests under valgrind
echo "Running tests under valgrind memcheck ..."
../test/test_valgrind.sh .. . memcheck

