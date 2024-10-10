#!/bin/bash
# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

[ "$1" != "" ] && PREFIX="$1" || PREFIX="exports-coverage"
[ "$2" != "" ] && OUTPUT_NAME="$2" || OUTPUT_NAME="total_coverage"

OPTS=""
for file in $(ls -1 ${PREFIX}-*); do
	OPTS="$OPTS -a $file"
done

set -ex

lcov -o $OUTPUT_NAME $OPTS
