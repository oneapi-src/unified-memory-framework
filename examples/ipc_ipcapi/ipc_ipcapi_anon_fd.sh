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

# The ipc_ipcapi_anon_fd example requires using pidfd_getfd(2)
# to obtain a duplicate of another process's file descriptor.
# Permission to duplicate another process's file descriptor
# is governed by a ptrace access mode PTRACE_MODE_ATTACH_REALCREDS check (see ptrace(2))
# In the producer binary used in this example prctl(PR_SET_PTRACER, getppid()) is used
# to allow consumer to duplicate file descriptor of producer.

UMF_LOG_VAL="level:debug;flush:debug;output:stderr;pid:yes"

echo "Starting ipc_ipcapi_anon_fd CONSUMER on port $PORT ..."
UMF_LOG=$UMF_LOG_VAL ./umf_example_ipc_ipcapi_consumer $PORT &

echo "Waiting 1 sec ..."
sleep 1

echo "Starting ipc_ipcapi_anon_fd PRODUCER on port $PORT ..."
UMF_LOG=$UMF_LOG_VAL ./umf_example_ipc_ipcapi_producer $PORT
