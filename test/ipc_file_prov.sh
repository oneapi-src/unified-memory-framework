#
# Copyright (C) 2024 Intel Corporation
#
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

#!/bin/bash

set -e

FILE_NAME="/tmp/umf_file_provider_$$"

# port should be a number from the range <1024, 65535>
PORT=$(( 1024 + ( $$ % ( 65535 - 1024 ))))

UMF_LOG_VAL="level:debug;flush:debug;output:stderr;pid:yes"

# make sure the temp file does not exist
rm -f ${FILE_NAME}

echo "Starting ipc_file_prov CONSUMER on port $PORT ..."
UMF_LOG=$UMF_LOG_VAL ./umf_test-ipc_file_prov_consumer $PORT ${FILE_NAME}_consumer &

echo "Waiting 1 sec ..."
sleep 1

echo "Starting ipc_file_prov PRODUCER on port $PORT ..."
UMF_LOG=$UMF_LOG_VAL ./umf_test-ipc_file_prov_producer $PORT ${FILE_NAME}_producer

# remove the SHM file
rm -f ${FILE_NAME}
