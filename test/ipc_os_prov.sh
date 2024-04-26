#
# Copyright (C) 2024 Intel Corporation
#
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

#!/bin/bash

# port should be a number from the range <1024, 65535>
PORT=$(( 1024 + ( $$ % ( 65535 - 1024 ))))

# The ipc_os_prov example requires using pidfd_getfd(2)
# to obtain a duplicate of another process's file descriptor.
# Permission to duplicate another process's file descriptor
# is governed by a ptrace access mode PTRACE_MODE_ATTACH_REALCREDS check (see ptrace(2))
# that can be changed using the /proc/sys/kernel/yama/ptrace_scope interface.
PTRACE_SCOPE_FILE="/proc/sys/kernel/yama/ptrace_scope"
VAL=0
if [ -f $PTRACE_SCOPE_FILE ]; then
	PTRACE_SCOPE_VAL=$(cat $PTRACE_SCOPE_FILE)
	if [ $PTRACE_SCOPE_VAL -ne $VAL ]; then
		echo "Setting ptrace_scope to 0 (classic ptrace permissions) ..."
		echo "$ sudo bash -c \"echo $VAL > $PTRACE_SCOPE_FILE\""
		sudo bash -c "echo $VAL > $PTRACE_SCOPE_FILE"
	fi
	PTRACE_SCOPE_VAL=$(cat $PTRACE_SCOPE_FILE)
	if [ $PTRACE_SCOPE_VAL -ne $VAL ]; then
		echo "SKIP: setting ptrace_scope to 0 (classic ptrace permissions) FAILED - skipping the test"
		exit 0
	fi
fi

UMF_LOG_VAL="level:debug;flush:debug;output:stderr;pid:yes"

echo "Starting ipc_os_prov CONSUMER on port $PORT ..."
UMF_LOG=$UMF_LOG_VAL ./umf_test-ipc_os_prov_consumer $PORT &

echo "Waiting 1 sec ..."
sleep 1

echo "Starting ipc_os_prov PRODUCER on port $PORT ..."
UMF_LOG=$UMF_LOG_VAL ./umf_test-ipc_os_prov_producer $PORT
