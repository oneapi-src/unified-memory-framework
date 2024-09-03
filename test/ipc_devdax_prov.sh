#
# Copyright (C) 2024 Intel Corporation
#
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

#!/bin/bash

set -e

if [ "$UMF_TESTS_DEVDAX_PATH" = "" ]; then
	echo "Test skipped, UMF_TESTS_DEVDAX_PATH is not set"
	exit 0
fi

if [ "$UMF_TESTS_DEVDAX_SIZE" = "" ]; then
	echo "Test skipped, UMF_TESTS_DEVDAX_SIZE is not set"
	exit 0
fi

# port should be a number from the range <1024, 65535>
PORT=$(( 1024 + ( $$ % ( 65535 - 1024 ))))

UMF_LOG_VAL="level:debug;flush:debug;output:stderr;pid:yes"

echo "Starting ipc_devdax_prov CONSUMER on port $PORT ..."
UMF_LOG=$UMF_LOG_VAL ./umf_test-ipc_devdax_prov_consumer $PORT &

echo "Waiting 1 sec ..."
sleep 1

echo "Starting ipc_devdax_prov PRODUCER on port $PORT ..."
UMF_LOG=$UMF_LOG_VAL ./umf_test-ipc_devdax_prov_producer $PORT
