#!/bin/bash
# Copyright (C) 2026 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# Builds the static hwloc library bundled with UMF for Linux x86-64 and copies
# it, together with its headers, into src/deps/hwloc. Keep the configure
# options in sync with the hwloc ExternalProject in the top-level CMakeLists.txt.

set -euo pipefail

HWLOC_REPO=${HWLOC_REPO:-https://github.com/open-mpi/hwloc.git}
HWLOC_TAG=${HWLOC_TAG:-hwloc-2.13.0}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DEPS_DIR=$(dirname "$SCRIPT_DIR")
UMF_ROOT=$(cd "$SCRIPT_DIR/../../../.." && pwd)
TEMP_DIR="$SCRIPT_DIR/temp"
SRC_DIR="$TEMP_DIR/src"
INSTALL_DIR="$TEMP_DIR/install"

if [ "$(uname -m)" != "x86_64" ]; then
    echo "Error: the bundled hwloc is built only for x86-64" >&2
    exit 1
fi

rm -rf "$TEMP_DIR"
trap 'rm -rf "$TEMP_DIR"' EXIT

git clone --depth 1 --branch "$HWLOC_TAG" "$HWLOC_REPO" "$SRC_DIR"
git -C "$SRC_DIR" apply "$UMF_ROOT/cmake/fix_coverity_issues.patch"

cd "$SRC_DIR"
./autogen.sh
# -ffile-prefix-map keeps local build paths out of the committed archive
HWLOC_FLAGS="-O2 -fPIC -ffile-prefix-map=$SRC_DIR=hwloc"
./configure --prefix="$INSTALL_DIR" --runstatedir=/run \
    --enable-static=yes --enable-shared=no \
    --with-hwloc-symbol-prefix=umf_hwloc_ --disable-libxml2 \
    --disable-pci --disable-levelzero --disable-opencl \
    --disable-cuda --disable-nvml --disable-libudev --disable-rsmi \
    CFLAGS="$HWLOC_FLAGS" CXXFLAGS="$HWLOC_FLAGS"
make -j "$(nproc)"
make install

unprefixed=$(nm -g --defined-only "$INSTALL_DIR/lib/libhwloc.a" |
    awk 'NF == 3 {print $3}' | grep -v '^umf_hwloc_' || true)
if [ -n "$unprefixed" ]; then
    echo "Error: hwloc defines symbols without the umf_hwloc_ prefix:" >&2
    echo "$unprefixed" >&2
    exit 1
fi

cp "$INSTALL_DIR/lib/libhwloc.a" "$SCRIPT_DIR/"
mkdir -p "$SCRIPT_DIR/include/hwloc/autogen"
cp "$INSTALL_DIR/include/hwloc/autogen/config.h" \
    "$SCRIPT_DIR/include/hwloc/autogen/"
mkdir -p "$DEPS_DIR/include/hwloc"
cp "$INSTALL_DIR/include/hwloc.h" "$DEPS_DIR/include/"
cp "$INSTALL_DIR"/include/hwloc/*.h "$DEPS_DIR/include/hwloc/"

echo "Bundled hwloc ($HWLOC_TAG) updated in $DEPS_DIR"
