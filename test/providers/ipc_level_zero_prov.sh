#
# Copyright (C) 2024-2025 Intel Corporation
#
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

#!/bin/bash

set -e

# port should be a number from the range <1024, 65535>
PORT=$(( 1024 + ( $$ % ( 65535 - 1024 ))))

UMF_LOG_VAL="level:debug;flush:debug;output:stderr;pid:yes"

echo "Starting ipc_level_zero_prov CONSUMER on port $PORT ..."
UMF_LOG=$UMF_LOG_VAL ./test_ipc_level_zero_prov_consumer $PORT &

echo "Waiting 1 sec ..."
sleep 1

echo "Starting ipc_level_zero_prov PRODUCER on port $PORT ..."
UMF_LOG=$UMF_LOG_VAL ./test_ipc_level_zero_prov_producer $PORT
