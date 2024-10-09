#!/bin/bash
# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set -e

WORKSPACE=$1
BUILD_DIR=$2
TOOL=$3

function print_usage() {
	echo "$(basename $0) - run all UMF tests under a valgrind tool (memcheck, drd or helgrind)"
	echo "This script looks for './test/umf_test-*' test executables in the UMF build directory."
	echo "Usage: $(basename $0) <workspace_dir> <build_dir> <memcheck|drd|helgrind>"
}

if ! valgrind --version > /dev/null; then
	echo "error: valgrind not found"
	exit 1
fi

if [ "$3" = "" ]; then
	echo -e "error: too few arguments\n"
	print_usage
	exit 1
fi

if [ ! -f $WORKSPACE/README.md ]; then
	echo -e "error: incorrect <workspace_dir>: $WORKSPACE\n"
	print_usage
	exit 1
fi

if [ $(ls -1 ${BUILD_DIR}/test/umf_test-* 2>/dev/null | wc -l) -eq 0 ]; then
	echo -e "error: UMF tests ./test/umf_test-* not found in the build directory: ${BUILD_DIR}\n"
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
	echo -e "error: unknown valgrind tool: $TOOL\n"
	print_usage
	exit 1
	;;
esac

WORKSPACE=$(realpath $WORKSPACE)
BUILD_DIR=$(realpath $BUILD_DIR)

cd ${BUILD_DIR}/test/
mkdir -p cpuid

echo "Gathering data for hwloc so it can be run under valgrind:"
hwloc-gather-cpuid ./cpuid

echo
echo "Working directory: $(pwd)"
echo "Running: \"valgrind $OPTION\" for the following tests:"

ANY_TEST_FAILED=0
rm -f umf_test-*.log umf_test-*.err

for test in $(ls -1 umf_test-*); do
	[ ! -x $test ] && continue
	echo "$test - starting ..."
	echo -n "$test "
	LOG=${test}.log
	ERR=${test}.err
	SUP="${WORKSPACE}/test/supp/${TOOL}-${test}.supp"
	OPT_SUP=""
	[ -f ${SUP} ] && OPT_SUP="--suppressions=${SUP}" && echo -n "(${TOOL}-${test}.supp) "

	# skip tests incompatible with valgrind
	FILTER=""
	case $test in
	umf_test-ipc_os_prov_*)
		echo "- SKIPPED"
		continue; # skip testing helper binaries used by the ipc_os_prov_* tests
		;;
	umf_test-ipc_devdax_prov_*)
		echo "- SKIPPED"
		continue; # skip testing helper binaries used by the ipc_devdax_prov_* tests
		;;
	umf_test-ipc_file_prov_*)
		echo "- SKIPPED"
		continue; # skip testing helper binaries used by the ipc_file_prov_* tests
		;;
	umf_test-memspace_host_all)
		FILTER='--gtest_filter="-*allocsSpreadAcrossAllNumaNodes"'
		;;
	umf_test-provider_os_memory)
		FILTER='--gtest_filter="-osProviderTest/umfIpcTest*"'
		;;
	umf_test-provider_os_memory_config)
		FILTER='--gtest_filter="-*protection_flag_none:*protection_flag_read:*providerConfigTestNumaMode*"'
		;;
	umf_test-memspace_highest_capacity)
		FILTER='--gtest_filter="-*highestCapacityVerify*"'
		;;
	umf_test-provider_os_memory_multiple_numa_nodes)
		FILTER='--gtest_filter="-testNuma.checkModeInterleave*:testNumaNodesAllocations/testNumaOnEachNode.checkNumaNodesAllocations*:testNumaNodesAllocations/testNumaOnEachNode.checkModePreferred*:testNumaNodesAllocations/testNumaOnEachNode.checkModeInterleaveSingleNode*:testNumaNodesAllocationsAllCpus/testNumaOnEachCpu.checkModePreferredEmptyNodeset*:testNumaNodesAllocationsAllCpus/testNumaOnEachCpu.checkModeLocal*"'
		;;
	umf_test-memspace_highest_bandwidth)
		FILTER='--gtest_filter="-*allocLocalMt*"'
		;;
	umf_test-memspace_lowest_latency)
		FILTER='--gtest_filter="-*allocLocalMt*"'
		;;
	esac

	[ "$FILTER" != "" ] && echo -n "($FILTER) "

	LAST_TEST_FAILED=0

	if ! HWLOC_CPUID_PATH=./cpuid valgrind $OPTION $OPT_SUP --gen-suppressions=all ./$test $FILTER >$LOG 2>&1; then
		LAST_TEST_FAILED=1
		ANY_TEST_FAILED=1
		echo "(valgrind FAILED) "
		echo "Command: HWLOC_CPUID_PATH=./cpuid valgrind $OPTION $OPT_SUP --gen-suppressions=all ./$test $FILTER >$LOG 2>&1"
		echo "Output:"
		cat $LOG
		echo "====================="
		echo
	fi || true
	# grep for "ERROR SUMMARY" with errors (there can be many lines with "ERROR SUMMARY")
	grep -e "ERROR SUMMARY:" $LOG | grep -v -e "ERROR SUMMARY: 0 errors from 0 contexts" > $ERR || true
	if [ $LAST_TEST_FAILED -eq 0 -a $(cat $ERR | wc -l) -eq 0 ]; then
		echo "- OK"
		rm -f $LOG $ERR
	else
		echo "- FAILED!"
		cat $ERR | cut -d' ' -f2-
		ANY_TEST_FAILED=1
	fi || true
done

rm -rf ${BUILD_DIR}/test/cpuid

[ $ANY_TEST_FAILED -eq 0 ] && echo PASSED && exit 0

echo
echo "======================================================================"
echo

for log in $(ls -1 umf_test-*.log); do
	echo ">>>>>>> LOG $log"
	cat $log
	echo
	echo
done

exit 1
