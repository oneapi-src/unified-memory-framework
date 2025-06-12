#!/bin/bash
# Copyright (C) 2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# install_oneAPI.sh - Script for installing Intel oneAPI from the official repository

apt-get update
apt-get install -y gpg-agent gnupg wget
wget -O- https://apt.repos.intel.com/intel-gpg-keys/GPG-PUB-KEY-INTEL-SW-PRODUCTS.PUB | gpg --dearmor -o /usr/share/keyrings/oneapi-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/oneapi-archive-keyring.gpg] https://apt.repos.intel.com/oneapi all main' > /etc/apt/sources.list.d/oneAPI.list
apt-get update
apt-get install -y intel-oneapi-ippcp-devel intel-oneapi-ipp-devel intel-oneapi-common-oneapi-vars intel-oneapi-compiler-dpcpp-cpp
