#
# Copyright (C) 2024 Intel Corporation
#
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

#!/bin/bash

set -e

# port should be a number from the range <1024, 65535>
PORT=$(( 1024 + ( $$ % ( 65535 - 1024 ))))

# The ipc_level_zero_prov test requires using pidfd_getfd(2)
# to obtain a duplicate of another process's file descriptor.
# Permission to duplicate another process's file descriptor
# is governed by a ptrace access mode PTRACE_MODE_ATTACH_REALCREDS check (see ptrace(2))
# that can be changed using the /proc/sys/kernel/yama/ptrace_scope interface.
PTRACE_SCOPE_FILE="/proc/sys/kernel/yama/ptrace_scope"
VAL=0
if [ -f $PTRACE_SCOPE_FILE ]; then
	PTRACE_SCOPE_VAL=$(cat $PTRACE_SCOPE_FILE)
	if [ $PTRACE_SCOPE_VAL -ne $VAL ]; then
		echo "SKIP: ptrace_scope is not set to 0 (classic ptrace permissions) - skipping the test"
		exit 125 # skip code defined in CMakeLists.txt
	fi
fi

UMF_LOG_VAL="level:debug;flush:debug;output:stderr;pid:yes"

echo "Starting ipc_level_zero_prov CONSUMER on port $PORT ..."
UMF_LOG=$UMF_LOG_VAL ./umf_test-ipc_level_zero_prov_consumer $PORT &

echo "Waiting 1 sec ..."
sleep 1

echo "Starting ipc_level_zero_prov PRODUCER on port $PORT ..."
UMF_LOG=$UMF_LOG_VAL ./umf_test-ipc_level_zero_prov_producer $PORT
