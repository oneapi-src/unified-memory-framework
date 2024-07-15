#!/bin/bash
# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set -e

WORKSPACE=$1
BUILD_DIR=$2
INSTALL_DIR=$3

echo "Running: $0 $*"

function print_usage() {
	echo "$(basename $0) - test all examples standalone"
	echo "Usage: $(basename $0) <workspace_dir> <build_dir> <install_dir> <list-of-examples-to-run>"
}

if [ "$3" == "" ]; then
	print_usage
	echo -e "Error: too few arguments\n"
	exit 1
fi

if [ "$4" == "" ]; then
	print_usage
	echo "No examples to run!"
	exit 0
fi

if [ ! -f $WORKSPACE/README.md ]; then
	echo -e "error: incorrect <workspace_dir>: $WORKSPACE\n"
	print_usage
	exit 1
fi

WORKSPACE=$(realpath $WORKSPACE)
BUILD_DIR=$(realpath $BUILD_DIR)
INSTALL_DIR=$(realpath $INSTALL_DIR)

shift 3
EXAMPLES="$*"
echo "Examples to run: $EXAMPLES"
echo

cd ${BUILD_DIR}
echo "DIR=$(pwd)"

set -x
make -j$(nproc) install
set +x

for ex in $EXAMPLES; do
	SRC_DIR="${WORKSPACE}/examples/$ex"
	BLD_DIR="${BUILD_DIR}/examples-standalone/$ex"

	if [ ! -d $SRC_DIR ]; then
		echo "Example does not exist: $ex ($SRC_DIR)"
		exit 1
	fi

	echo
	echo "Building and running the example: $ex"
	echo

	set -x
	rm -rf $BLD_DIR
	mkdir -p $BLD_DIR
	cd $BLD_DIR
	CMAKE_PREFIX_PATH="$INSTALL_DIR" cmake $SRC_DIR
	make -j$(nproc)
	ctest --output-on-failure
	set +x
done
