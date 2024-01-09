#!/bin/bash
# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set -e

USAGE_STR="Usage: $(basename $0) <workspace_dir> <build_dir> <install_dir> <build_type:Release|Debug> <shared_library:ON|OFF>"

if [ "$5" == "" ]; then
	echo $USAGE_STR
	exit 1
fi

WORKSPACE=$(realpath $1)
BUILD_DIR=$(realpath $2)
INSTALL_DIR=$(realpath $3)
BUILD_TYPE=$4
SHARED_LIB=$5

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

if [ -d $INSTALL_DIR ]; then
	echo "Incorrect <install_dir> (it should not exist): $INSTALL_DIR"
	echo $USAGE_STR
	exit 1
fi

if [ "$BUILD_TYPE" != "Release" -a "$BUILD_TYPE" != "Debug" ]; then
	echo "Incorrect <build_type> argument: $BUILD_TYPE"
	echo $USAGE_STR
	exit 1
fi

if [ "$SHARED_LIB" != "ON" -a "$SHARED_LIB" != "OFF" ]; then
	echo "Incorrect <shared_library> argument: $SHARED_LIB"
	echo $USAGE_STR
	exit 1
fi

[ "$BUILD_TYPE" == "Release" ] && BUILD_TYPE_STR="release" || BUILD_TYPE_STR="debug"
[ "$SHARED_LIB" == "ON" ] && LIB_EXT_STR="so" || LIB_EXT_STR="a"

echo "WORKSPACE=$WORKSPACE"
echo "BUILD_DIR=$BUILD_DIR"
echo "INSTALL_DIR=$INSTALL_DIR"
echo "BUILD_TYPE=$BUILD_TYPE"
echo "BUILD_TYPE_STR=$BUILD_TYPE_STR"
echo "SHARED_LIB=$SHARED_LIB"
echo "LIB_EXT_STR=$LIB_EXT_STR"

set -x

TEMPLATE_INSTALL_FILES="${WORKSPACE}/test/test_make_install.txt"
INSTALLED_FILES="${BUILD_DIR}/install-files.txt"
MATCH_INSTALLED_FILES="${BUILD_DIR}/install-files-match.txt"

cp -f ${TEMPLATE_INSTALL_FILES} ${MATCH_INSTALLED_FILES}
sed -i "s/@BUILD_TYPE_STR@/$BUILD_TYPE_STR/g" ${MATCH_INSTALLED_FILES}
sed -i "s/@LIB_EXT_STR@/$LIB_EXT_STR/g" ${MATCH_INSTALLED_FILES}

mkdir ${INSTALL_DIR}
cd ${BUILD_DIR}
make install prefix=${INSTALL_DIR}

cd ${INSTALL_DIR}
find | sort > ${INSTALLED_FILES}

# check if 'make install' installed all and only required files
diff ${INSTALLED_FILES} ${MATCH_INSTALLED_FILES} || exit 1
set +x

echo "Success"
