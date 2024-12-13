#!/bin/bash
# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

BINARY=$1

if [ "$BINARY" = "" ]; then
	echo "Usage: $(basename $0) <binary_name>"
	exit 1
fi

if ! which strings >/dev/null; then
	echo "strings command not found. Please install the binutils package."
	exit 1
fi

# check if the binary is statically linked with libumf
# or if it is the UMF library itself
if [ $(strings $BINARY | grep -c -e "@(#) Intel(R) UMF") -gt 0 ]; then
	BIN_NO_LINK=$(readlink -f "$BINARY")
	FILE_INFO=$(file $BIN_NO_LINK)
	if [[ "$FILE_INFO" == *"libumf.so"*"ELF 64-bit LSB shared object"*"dynamically linked"* ]]; then
		echo "$BINARY is the UMF library ($BIN_NO_LINK)."
	else
		echo "$BINARY is statically linked with the UMF library."
	fi

	echo "Strings in $BIN_NO_LINK:"
	strings $BIN_NO_LINK | grep "@(#) Intel(R) UMF"
	exit 0
fi

# check if the binary is dynamically linked with libumf
if [ $(ldd $BINARY | grep -c -e "libumf.so") -gt 0 ]; then
	UMF_LIB=$(ldd $BINARY | grep libumf.so | awk '{ print $3 }')
	UMF_LIB=$(readlink -f "$UMF_LIB")
	echo "$BINARY is dynamically linked with the UMF library ($UMF_LIB)."
	echo "Strings in $UMF_LIB:"
	strings $UMF_LIB | grep "@(#) Intel(R) UMF"
	exit 0
fi

echo "$BINARY does not contain magic strings of the UMF library."
