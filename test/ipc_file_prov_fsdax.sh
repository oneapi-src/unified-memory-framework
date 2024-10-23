#
# Copyright (C) 2024 Intel Corporation
#
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

#!/bin/bash

set -e

if [ "$UMF_TESTS_FSDAX_PATH" = "" ]; then
	echo "$0: Test skipped, UMF_TESTS_FSDAX_PATH is not set";
	exit 0
fi

if [ "$UMF_TESTS_FSDAX_PATH_2" = "" ]; then
	echo "$0: Test skipped, UMF_TESTS_FSDAX_PATH_2 is not set";
	exit 0
fi

FILE_NAME="$UMF_TESTS_FSDAX_PATH"
FILE_NAME_2="$UMF_TESTS_FSDAX_PATH_2"

# port should be a number from the range <1024, 65535>
PORT=$(( 1024 + ( $$ % ( 65535 - 1024 ))))

UMF_LOG_VAL="level:debug;flush:debug;output:stderr;pid:yes"

# make sure the temp file does not exist
rm -f ${FILE_NAME}

echo "Starting ipc_file_prov_fsdax CONSUMER on port $PORT ..."
UMF_LOG=$UMF_LOG_VAL ./umf_test-ipc_file_prov_consumer $PORT $FILE_NAME "FSDAX" &

echo "Waiting 1 sec ..."
sleep 1

echo "Starting ipc_file_prov_fsdax PRODUCER on port $PORT ..."
UMF_LOG=$UMF_LOG_VAL ./umf_test-ipc_file_prov_producer $PORT $FILE_NAME_2 "FSDAX"

# remove the SHM file
rm -f ${FILE_NAME}
