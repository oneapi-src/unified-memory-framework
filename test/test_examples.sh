#!/bin/bash
# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set -e

SOURCE_DIR=$1
BUILD_DIR=$2
INSTALL_DIR=$3
CMAKE_INSTALL_PREFIX=$4
STANDALONE_CMAKE_OPTIONS=$5

echo "Running: $0 $*"

function print_usage() {
	echo "$(basename $0) - test all examples standalone"
	echo "Usage: $(basename $0) <source_dir> <build_dir> <install_dir> <CMAKE_INSTALL_PREFIX> <standalone_cmake_options> <list-of-examples-to-run>"
}

if [ "$6" = "" ]; then
	print_usage
	echo -e "Error: too few arguments\n"
	exit 1
fi

if [ ! -f $SOURCE_DIR/README.md ]; then
	echo -e "error: incorrect <source_dir>: $SOURCE_DIR\n"
	print_usage
	exit 1
fi

mkdir -p ${INSTALL_DIR}/${CMAKE_INSTALL_PREFIX}

SOURCE_DIR=$(realpath $SOURCE_DIR)
BUILD_DIR=$(realpath $BUILD_DIR)
INSTALL_DIR=$(realpath $INSTALL_DIR)

echo "SOURCE_DIR=$SOURCE_DIR"
echo "BUILD_DIR=$BUILD_DIR"
echo "CMAKE_INSTALL_PREFIX=$CMAKE_INSTALL_PREFIX"
echo "INSTALL_DIR=$INSTALL_DIR"
echo "STANDALONE_CMAKE_OPTIONS=$STANDALONE_CMAKE_OPTIONS"

shift 5
EXAMPLES="$*"
echo "Examples to run: $EXAMPLES"
echo

cd ${BUILD_DIR}
echo "DIR=$(pwd)"

echo "Installing UMF into the directory: ${INSTALL_DIR}/${CMAKE_INSTALL_PREFIX}"
set -x
make DESTDIR=$INSTALL_DIR -j$(nproc) install
set +x

for ex in $EXAMPLES; do
	SRC_DIR="${SOURCE_DIR}/examples/$ex"
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
	CMAKE_PREFIX_PATH="${INSTALL_DIR}/${CMAKE_INSTALL_PREFIX}" cmake $SRC_DIR $STANDALONE_CMAKE_OPTIONS
	make -j$(nproc)
	ctest --output-on-failure
	set +x
done
