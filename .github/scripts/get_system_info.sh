#!/bin/bash
# Copyright (C) 2024-2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# get_system_info.sh - Script for printing system info

function check_L0_version {
    if command -v dpkg &> /dev/null; then
        dpkg -l | grep level-zero && return
    fi

    if command -v rpm &> /dev/null; then
        rpm -qa | grep level-zero && return
    fi

    if command -v zypper &> /dev/null; then
        zypper se level-zero && return
    fi

    echo "level-zero not installed"
}

function system_info {
	echo "**********system_info**********"
	cat /etc/os-release | grep -oP "PRETTY_NAME=\K.*"
	cat /proc/version

	# echo "**********SYCL-LS**********"
	# source /opt/intel/oneapi/setvars.sh
	# sycl-ls

	echo "**********numactl topology**********"
	numactl -H

	echo "**********VGA info**********"
	lspci | grep -i VGA

	# echo "**********CUDA Version**********"
	# if command -v nvidia-smi &> /dev/null; then
	# 	nvidia-smi
	# else
	# 	echo "CUDA not installed"
	# fi

	echo "**********L0 Version**********"
	check_L0_version

	# echo "**********ROCm Version**********"
	# if command -v rocminfo &> /dev/null; then
	# 	rocminfo
	# else
	# 	echo "ROCm not installed"
	# fi

	echo "******OpenCL*******"
	# The driver version of OpenCL Graphics is the compute-runtime version
	clinfo || echo "OpenCL not installed"

	echo "**********/proc/cmdline**********"
	cat /proc/cmdline

	echo "**********CPU info**********"
	lscpu

	echo "**********/proc/meminfo**********"
	cat /proc/meminfo

	echo "**********env variables**********"
	echo "PATH=${PATH}"
	echo "CPATH=${CPATH}"
	echo "LD_LIBRARY_PATH=${LD_LIBRARY_PATH}"
	echo "LIBRARY_PATH=${LIBRARY_PATH}"
	echo "PKG_CONFIG_PATH=${PKG_CONFIG_PATH}"
	echo

	echo "******build tools versions*******"
	gcc --version 2>/dev/null || true
	echo
	clang --version 2>/dev/null || true
	echo
	make --version 2>/dev/null || true
	echo
	cmake --version 2>/dev/null || true
	echo

	echo "**********/proc/modules**********"
	cat /proc/modules

	echo "***************all installed packages***************"
	# Instructions below will return some minor errors, as they are dependent on the Linux distribution.
	zypper se --installed-only 2>/dev/null || true
	apt list --installed 2>/dev/null || true
	yum list installed 2>/dev/null || true
}

# Call the function above to print system info.
system_info
