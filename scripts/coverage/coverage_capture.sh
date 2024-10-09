#!/bin/bash
# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set -e

[ "$1" != "" ] && OUTPUT_NAME="$1" || OUTPUT_NAME="total_coverage"

set -x

lcov --capture --directory . --exclude "/usr/*" --exclude "*/build/_deps/*" --exclude "*/examples/*" --exclude "*/test/*" --exclude "*/src/critnib/*" --exclude "*/src/ravl/*" --exclude "*proxy_lib_new_delete.h*" --output-file $OUTPUT_NAME || \
	( echo && lcov --capture --directory . --exclude "/usr/*" --exclude "*/build/_deps/*" --exclude "*/examples/*" --exclude "*/test/*" --exclude "*/src/critnib/*" --exclude "*/src/ravl/*" --exclude "*proxy_lib_new_delete.h*" --ignore-errors mismatch,unused --output-file $OUTPUT_NAME )
