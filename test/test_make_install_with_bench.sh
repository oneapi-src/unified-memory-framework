#!/bin/bash
# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set -e

USAGE_STR="Usage: $(basename $0) <workspace_dir> <build_dir> <install_dir> <build_type:Release|Debug>"

if [ "$4" == "" ]; then
	echo $USAGE_STR
	exit 1
fi

WORKSPACE=$(realpath $1)
BUILD_DIR=$(realpath $2)
INSTALL_DIR=$(realpath $3)
BUILD_TYPE=$4

if [ ! -f $WORKSPACE/README.md ]; then
	echo "Incorrect <workspace_dir>: $WORKSPACE"
	echo $USAGE_STR
	exit 1
fi

if [ "$BUILD_DIR" == "$WORKSPACE" ]; then
	echo "Incorrect <build_dir>: $BUILD_DIR"
	echo $USAGE_STR
	exit 1
fi

if [ ! -d $INSTALL_DIR ]; then
	echo "Incorrect <install_dir> (it should exist): $INSTALL_DIR"
	echo $USAGE_STR
	exit 1
fi

if [ "$BUILD_TYPE" != "Release" -a "$BUILD_TYPE" != "Debug" ]; then
	echo "Incorrect <build_type> argument: $BUILD_TYPE"
	echo $USAGE_STR
	exit 1
fi

[ "$BUILD_TYPE" == "Release" ] && BUILD_TYPE_STR="release" || BUILD_TYPE_STR="debug"

echo "WORKSPACE=$WORKSPACE"
echo "BUILD_DIR=$BUILD_DIR"
echo "INSTALL_DIR=$INSTALL_DIR"
echo "BUILD_TYPE=$BUILD_TYPE"
echo "BUILD_TYPE_STR=$BUILD_TYPE_STR"

set -ex

# clean the build directory
rm -rf ${BUILD_DIR}/*
ls -al

cmake .. -DCMAKE_INSTALL_PREFIX="${INSTALL_DIR}" -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -DUMF_BUILD_SHARED_LIBRARY=ON -DUMF_BUILD_TESTS=OFF -DUMF_BUILD_BENCHMARKS=ON
make -j $(nproc)
make install
./benchmark/ubench && echo "Benchmark succeeded as expected" || exit 1

# remove libumf.so
ldd ./benchmark/ubench
rm -f $(ldd ./benchmark/ubench | grep -e "libumf.so" | awk '{print $3}')

./benchmark/ubench && exit 1 || echo "Benchmark failed as expected"
LD_LIBRARY_PATH=${INSTALL_DIR}/lib/ ./benchmark/ubench && echo "Benchmark succeeded as expected" || exit 1

echo "Success"
