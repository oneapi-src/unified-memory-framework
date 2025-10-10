#!/usr/bin/env python3
#
# Copyright (C) 2025 Intel Corporation
#
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

import os
import sys
import time
import subprocess  # nosec B404
import platform


def main():
    # Port should be a number from the range <1024, 65535>
    # Use PROCESS_ID environment variable if set, otherwise use current PID
    pid = int(os.environ.get("PROCESS_ID", os.getpid()))
    port = 1024 + (pid % (65535 - 1024))

    # Set UMF_LOG environment variable
    os.environ["UMF_LOG"] = "level:debug;flush:debug;output:stderr;pid:yes"

    build_type = os.environ.get("BUILD_TYPE", "Debug")

    # Determine executable extension based on platform
    exe_ext = ".exe" if platform.system() == "Windows" else ""

    print(f"Starting test_ipc_cuda_prov CONSUMER on port {port} ...")

    # Start consumer process
    consumer_cmd = [f"./{build_type}/test_ipc_cuda_prov_consumer{exe_ext}", str(port)]
    with open("consumer_log.txt", "w") as consumer_log:
        consumer_proc = subprocess.Popen(  # nosec
            consumer_cmd, stdout=consumer_log, stderr=subprocess.STDOUT
        )

    print("Waiting 5 sec ...")
    time.sleep(5)

    print(f"Starting test_ipc_cuda_prov PRODUCER on port {port} ...")

    # Start producer process
    producer_cmd = [f"./{build_type}/test_ipc_cuda_prov_producer{exe_ext}", str(port)]
    with open("producer_log.txt", "w") as producer_log:
        producer_proc = subprocess.Popen(  # nosec
            producer_cmd, stdout=producer_log, stderr=subprocess.STDOUT
        )

    print("Waiting 10 sec for the consumer and producer to finish ...")
    time.sleep(10)

    # Wait for processes to complete
    consumer_proc.wait()
    producer_proc.wait()

    print("Test finished")

    # Display consumer log
    print("Consumer log:")
    try:
        with open("consumer_log.txt", "r") as f:
            print(f.read())
    except FileNotFoundError:
        print("consumer_log.txt not found")

    # Display producer log
    print("Producer log:")
    try:
        with open("producer_log.txt", "r") as f:
            print(f.read())
    except FileNotFoundError:
        print("producer_log.txt not found")

    # Check for errors in logs
    error_found = False
    for log_file in ["consumer_log.txt", "producer_log.txt"]:
        try:
            with open(log_file, "r") as f:
                content = f.read().upper()
                if "ERROR" in content or "FATAL" in content:
                    error_found = True
                    break
        except FileNotFoundError:
            continue

    if error_found:
        print("Test failed: ERROR or FATAL found in logs.")
        sys.exit(1)

    print("Test passed: No errors found in logs.")


if __name__ == "__main__":
    main()
