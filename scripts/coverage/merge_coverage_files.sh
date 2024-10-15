#!/bin/bash
# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#
# Arguments: <PREFIX> <OUTPUT_NAME>
#
# This script looks for "${PREFIX}-*" lcov output files in the current directory,
# merges them and saves the merged output in the $OUTPUT_NAME file.
#

[ "$1" != "" ] && PREFIX="$1" || PREFIX="exports-coverage"
[ "$2" != "" ] && OUTPUT_NAME="$2" || OUTPUT_NAME="total_coverage"

OPTS=""
for file in $(ls -1 ${PREFIX}-*); do
	OPTS="$OPTS -a $file"
done

set -x

lcov $OPTS -o $OUTPUT_NAME  || \
	( echo "RETRY after ERROR !!!:" && \
	lcov $OPTS \
	--ignore-errors mismatch,unused,negative,corrupt \
	--output-file $OUTPUT_NAME )
