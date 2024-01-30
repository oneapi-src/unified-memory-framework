#!/bin/bash
# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set -e

TOOL=$1

function print_usage() {
	echo "$(basename $0) - run UMF tests under valgrind tools (memcheck, drd or helgrind)"
	echo "This script must be run in the UMF build directory. It looks for './test/umf_test-*' test executables."
	echo "Usage: $(basename $0) <memcheck|drd|helgrind>"
}

if ! valgrind --version > /dev/null; then
	echo "error: valgrind not found"
	exit 1
fi

if [ $(ls -1 ./test/umf_test-* 2>/dev/null | wc -l) -eq 0 ]; then
	echo "error: UMF tests ./test/umf_test-* not found (perhaps wrong directory)"
	print_usage
	exit 1
fi

if [ "$TOOL" == "" ]; then
	echo "error: valgrind tool is missing"
	print_usage
	exit 1
fi

case $TOOL in
memcheck)
	OPTION="--leak-check=full"
	;;
drd)
	OPTION="--tool=drd"
	;;
helgrind)
	OPTION="--tool=helgrind"
	;;
*)
	echo "error: unknown tool: $TOOL"
	print_usage
	exit 1
	;;
esac

FAIL=0

mkdir -p cpuid

echo "Gathering data for hwloc so it can be run under valgrind:"
hwloc-gather-cpuid ./cpuid

echo "Running: \"valgrind $OPTION\" for the following tests:"

for tf in $(ls -1 ./test/umf_test-*); do
	[ ! -x $tf ] && continue
	echo -n "$tf "
	LOG=${tf}.log
	HWLOC_CPUID_PATH=./cpuid valgrind $OPTION $tf >$LOG 2>&1 || echo -n "(valgrind failed) "
	if grep -q -e "ERROR SUMMARY: 0 errors from 0 contexts" $LOG; then
		echo "- OK"
		rm $LOG
	else
		echo "- FAILED! : $(grep -e "ERROR SUMMARY:" $LOG | cut -d' ' -f2-)"
		FAIL=1
	fi || true
done

[ $FAIL -eq 0 ] && echo PASSED && exit 0

echo
echo "======================================================================"
echo

for log in $(ls -1 ./test/umf_test-*.log); do
	echo ">>>>>>> LOG $log"
	cat $log
	echo
	echo
done

exit 1
