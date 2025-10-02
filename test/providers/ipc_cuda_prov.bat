@echo off
rem
rem Copyright (C) 2025 Intel Corporation
rem 
rem Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
rem SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
rem

rem port should be a number from the range <1024, 65535>
set PID=%PROCESS_ID%
set /a PORT=1024 + (PID %% (65535 - 1024))

set UMF_LOG="level:debug;flush:debug;output:stderr;pid:yes"

echo "Starting test_ipc_cuda_prov CONSUMER on port %PORT% ..."
start "" cmd /c ".\%BUILD_TYPE%\test_ipc_cuda_prov_consumer %PORT% > consumer_log.txt 2>&1"

echo "Waiting 5 sec ..."
ping -n 5 -w 1000 localhost > nul

echo "Starting test_ipc_cuda_prov PRODUCER on port %PORT% ..."
start "" cmd /c ".\%BUILD_TYPE%\test_ipc_cuda_prov_producer %PORT% > producer_log.txt 2>&1"

echo "Waiting 10 sec for the consumer and producer to finish ..."
ping -n 10 -w 1000 localhost > nul

echo "Test finished"
echo "Consumer log:"
type consumer_log.txt

echo "Producer log:"
type producer_log.txt

findstr /I "ERROR FATAL" consumer_log.txt producer_log.txt >nul
if not errorlevel 1 (
	echo "Test failed: ERROR or FATAL found in logs."
	exit /b 1
)
