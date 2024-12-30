#!/bin/bash
# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set -e

WORKSPACE=$1
BUILD_DIR=$2
TOOL=$3
TESTS=$4

function print_usage() {
	echo "$(basename $0) - run UMF tests and examples under a valgrind tool (memcheck, drd or helgrind)"
	echo "Usage: $(basename $0) <workspace_dir> <build_dir> <memcheck|drd|helgrind> [tests_examples]"
	echo "Where:"
	echo
	echo "tests_examples - (optional) list of tests or examples to be run (paths relative to the <build_dir> build directory)."
	echo "                 If it is empty, all tests (./test/umf_test-*) and examples (./examples/umf_example_*)"
	echo "                 found in <build_dir> will be run."
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

cd ${BUILD_DIR}
mkdir -p cpuid

echo "Gathering data for hwloc so it can be run under valgrind:"
hwloc-gather-cpuid ./cpuid >/dev/null

echo
echo "Working directory: $(pwd)"
echo "Running: \"valgrind $OPTION\" for the following tests:"

ANY_TEST_FAILED=0
PATH_TESTS="./test/umf_test-*"
PATH_EXAMPLES="./examples/umf_example_*"

rm -f ${PATH_TESTS}.log ${PATH_TESTS}.err ${PATH_EXAMPLES}.log ${PATH_EXAMPLES}.err

[ "$TESTS" = "" ] && TESTS=$(ls -1 ${PATH_TESTS} ${PATH_EXAMPLES})

for test in $TESTS; do
	if [ ! -f $test ]; then
		echo
		echo "error: the $test (${BUILD_DIR}/$test) file does not exist"
		exit 1
	fi
	[ ! -x $test ] && continue
	echo "$test - starting ..."
	echo -n "$test "
	LOG=${test}.log
	ERR=${test}.err
	NAME=$(basename $test)
	SUP="${WORKSPACE}/test/supp/${TOOL}-${NAME}.supp"
	OPT_SUP=""
	[ -f ${SUP} ] && OPT_SUP="--suppressions=${SUP}" && echo -n "($(basename ${SUP})) "

	# skip tests incompatible with valgrind
	FILTER=""
	case $test in
	./test/umf_test-disjointPool)
		if [ "$TOOL" = "helgrind" ]; then
			# skip because of the assert in helgrind:
			# Helgrind: hg_main.c:308 (lockN_acquire_reader): Assertion 'lk->kind == LK_rdwr' failed.
			echo "- SKIPPED (helgrind only)"
			continue;
		fi
		;;
	./test/umf_test-ipc_os_prov_*)
		echo "- SKIPPED"
		continue; # skip testing helper binaries used by the ipc_os_prov_* tests
		;;
	./test/umf_test-ipc_devdax_prov_*)
		echo "- SKIPPED"
		continue; # skip testing helper binaries used by the ipc_devdax_prov_* tests
		;;
	./test/umf_test-ipc_file_prov_*)
		echo "- SKIPPED"
		continue; # skip testing helper binaries used by the ipc_file_prov_* tests
		;;
	./test/umf_test-memspace_host_all)
		FILTER='--gtest_filter="-*allocsSpreadAcrossAllNumaNodes"'
		;;
	./test/umf_test-provider_os_memory)
		FILTER='--gtest_filter="-osProviderTest/umfIpcTest*"'
		;;
	./test/umf_test-provider_os_memory_config)
		FILTER='--gtest_filter="-*protection_flag_none:*protection_flag_read:*providerConfigTestNumaMode*"'
		;;
	./test/umf_test-memspace_highest_capacity)
		FILTER='--gtest_filter="-*highestCapacityVerify*"'
		;;
	./test/umf_test-provider_os_memory_multiple_numa_nodes)
		FILTER='--gtest_filter="-testNuma.checkModeInterleave*:testNumaNodesAllocations/testNumaOnEachNode.checkNumaNodesAllocations*:testNumaNodesAllocations/testNumaOnEachNode.checkModePreferred*:testNumaNodesAllocations/testNumaOnEachNode.checkModeInterleaveSingleNode*:testNumaNodesAllocationsAllCpus/testNumaOnEachCpu.checkModePreferredEmptyNodeset*:testNumaNodesAllocationsAllCpus/testNumaOnEachCpu.checkModeLocal*"'
		;;
	./test/umf_test-memspace_highest_bandwidth)
		FILTER='--gtest_filter="-*allocLocalMt*"'
		;;
	./test/umf_test-memspace_lowest_latency)
		FILTER='--gtest_filter="-*allocLocalMt*"'
		;;
	./test/umf_test-memoryPool)
		FILTER='--gtest_filter="-*allocMaxSize*"'
		;;
	./examples/umf_example_ipc_ipcapi_*)
		echo "- SKIPPED"
		continue; # skip testing helper binaries used by the umf_example_ipc_ipcapi_* examples
		;;
	esac

	[ "$FILTER" != "" ] && echo -n "($FILTER) "

	LAST_TEST_FAILED=0
	set +e
	HWLOC_CPUID_PATH=./cpuid valgrind $OPTION $OPT_SUP --gen-suppressions=all $test $FILTER >$LOG 2>&1
	RET=$?
	set -e
	# 125 is the return code when the test is skipped
	if [ $RET -ne 0 -a $RET -ne 125 ]; then
		LAST_TEST_FAILED=1
		ANY_TEST_FAILED=1
		echo "(valgrind FAILED RV=$RET) "
		echo "Command: HWLOC_CPUID_PATH=./cpuid valgrind $OPTION $OPT_SUP --gen-suppressions=all $test $FILTER >$LOG 2>&1"
		echo "Output:"
		cat $LOG
		echo "====================="
		echo
	fi || true
	# grep for "ERROR SUMMARY" with errors (there can be many lines with "ERROR SUMMARY")
	grep -e "ERROR SUMMARY:" $LOG | grep -v -e "ERROR SUMMARY: 0 errors from 0 contexts" > $ERR || true
	if [ $LAST_TEST_FAILED -eq 0 -a $(cat $ERR | wc -l) -eq 0 ]; then
		[ $RET -eq 0 ] && echo "- OK" || echo "- SKIPPED"
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

for log in $(ls -1 ${PATH_TESTS}.log ${PATH_EXAMPLES}.log); do
	echo ">>>>>>> LOG $log"
	cat $log
	echo
	echo
done

exit 1
