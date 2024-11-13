#!/bin/bash
# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# If env var SHORT_RUN is set to true, part of the tests are skipped here.
# For coverage, OS_FULL_NAME env variable has to be set to the name of the OS.

set -e

COVERAGE=$1
XML_CONFIG_FILE=$2

CONFIG_NAME=$(echo $XML_CONFIG_FILE | cut -d. -f1) # remove the '.xml' extension
COVERAGE_DIR=${HOME}/coverage
mkdir -p $COVERAGE_DIR

# This is ${UMF_DIR}/scripts/qemu/run-build.sh file, so
UMF_DIR=$(dirname $0)/../..
cd $UMF_DIR
UMF_DIR=$(pwd)

# Drop caches, restores free memory on NUMA nodes
echo password | sudo sync;
echo password | sudo sh -c "/usr/bin/echo 3 > /proc/sys/vm/drop_caches"
# Set ptrace value for IPC test
echo password | sudo bash -c "echo 0 > /proc/sys/kernel/yama/ptrace_scope"

numactl -H

cd build
echo "## Running all tests ..."
ctest --verbose

echo "## Running tests bound to a numa node 0 and node 1 ..."
numactl -N 0 ctest --output-on-failure
numactl -N 1 ctest --output-on-failure

if [ "$COVERAGE" = "COVERAGE" ]; then
	COVERAGE_FILE_NAME=exports-coverage-qemu-${OS_FULL_NAME}-${CONFIG_NAME}
	echo "COVERAGE_FILE_NAME: $COVERAGE_FILE_NAME"
	../scripts/coverage/coverage_capture.sh $COVERAGE_FILE_NAME
	mv ./$COVERAGE_FILE_NAME $COVERAGE_DIR
fi

# run tests under valgrind only on long run or for default configuration
if [ "${SHORT_RUN}" != "true" ] || [ "${CONFIG_NAME}" == "default" ]; then
	echo "## Running tests under valgrind memcheck ..."
	../test/test_valgrind.sh .. . memcheck
fi
