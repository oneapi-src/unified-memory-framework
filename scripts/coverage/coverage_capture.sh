#!/bin/bash
# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# This script calculates coverage for a single build

set -e

[ "$1" != "" ] && OUTPUT_NAME="$1" || OUTPUT_NAME="output_coverage"

set -x

lcov --capture  --directory . \
--exclude "/usr/*" \
--exclude "*/build/*" \
--exclude "*/benchmark/*" \
--exclude "*/examples/*" \
--exclude "*/test/*" \
--exclude "*/src/critnib/*" \
--exclude "*/src/ravl/*" \
--exclude "*proxy_lib_new_delete.h" \
--output-file $OUTPUT_NAME || \
	( echo "RETRY after ERROR !!!:" && \
	lcov --capture --directory . \
	--exclude "/usr/*" \
	--exclude "*/build/*" \
	--exclude "*/benchmark/*" \
	--exclude "*/examples/*" \
	--exclude "*/test/*" \
	--exclude "*/src/critnib/*" \
	--exclude "*/src/ravl/*" \
	--exclude "*proxy_lib_new_delete.h" \
	--ignore-errors mismatch,unused,negative,corrupt \
	--output-file $OUTPUT_NAME )

# Most common UMF source code directory on most GH CI runners
COMMON_UMF_DIR=/home/runner/work/unified-memory-framework/unified-memory-framework

# Get the current UMF source code directory
# This is ${CURRENT_UMF_DIR}/scripts/coverage/coverage_capture.sh file, so
CURRENT_UMF_DIR=$(realpath $(dirname $0)/../..)

# Coverage (lcov) has to be run in the same directory on all runners:
# /home/runner/work/unified-memory-framework/unified-memory-framework/build
# to be able to merge all results, so we have to replace the paths if they are different:
if [ "$CURRENT_UMF_DIR" != "$COMMON_UMF_DIR" ]; then
	sed -i "s|$CURRENT_UMF_DIR|$COMMON_UMF_DIR|g" $OUTPUT_NAME
fi
