#
# Copyright (C) 2024 Intel Corporation
#
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

#!/bin/bash

set -e

UMF_LOG_VAL="level:debug;flush:debug;output:stderr;pid:yes"
UMF_PROXY_VAL="page.disposition=shared-shm"
LD_PRELOAD_VAL="../lib/libumf_proxy.so"

# port should be a number from the range <1024, 65535>
PORT=$(( 1024 + ( $$ % ( 65535 - 1024 ))))

echo "Starting CONSUMER on port $PORT ..."
UMF_LOG=$UMF_LOG_VAL ./umf_test-ipc_os_prov_consumer $PORT &

echo "Waiting 1 sec ..."
sleep 1

echo "Starting ipc_os_prov_proxy PRODUCER on port $PORT ..."
LD_PRELOAD=$LD_PRELOAD_VAL UMF_LOG=$UMF_LOG_VAL UMF_PROXY=$UMF_PROXY_VAL ./umf_test-ipc_os_prov_proxy $PORT
