#!/bin/bash
# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set -e

USAGE_STR="Usage: $(basename $0) <workspace_dir> <build_dir> <install_dir>"

if [ "$3" == "" ]; then
	echo $USAGE_STR
	exit 1
fi

WORKSPACE=$(realpath $1)
BUILD_DIR=$(realpath $2)
INSTALL_DIR=$(realpath $3)

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
	echo "Incorrect <install_dir> (it must exist): $INSTALL_DIR"
	echo $USAGE_STR
	exit 1
fi

echo "WORKSPACE=$WORKSPACE"
echo "BUILD_DIR=$BUILD_DIR"
echo "INSTALL_DIR=$INSTALL_DIR"

set -x

MATCH_UNINSTALLED_FILES="${WORKSPACE}/test/test_make_uninstall.txt"
UNINSTALLED_FILES="${BUILD_DIR}/uninstall-files.txt"

cd ${BUILD_DIR}
make uninstall

# check what files are left, there should be only empty directories left after 'make uninstall'
cd ${INSTALL_DIR}
find | sort > ${UNINSTALLED_FILES}

# check if 'make uninstall' left only empty directories
diff ${UNINSTALLED_FILES} ${MATCH_UNINSTALLED_FILES} || exit 1
set +x

echo "Success"
