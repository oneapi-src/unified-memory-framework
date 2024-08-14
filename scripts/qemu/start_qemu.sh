#!/bin/bash
# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set -e

# The config file name (should be located in ./configs/ sub-dir)
config_name=$1

# Parse the config file to get topology info and fix escaped single quotes
parsed_config=$(python3 "$(dirname $0)/parse_config.py" "$(dirname $0)/configs/${config_name}" | sed s/''\''/'/g)

set -x

sudo qemu-system-x86_64 \
    -drive file=./ubuntu-23.04-server-cloudimg-amd64.img,format=qcow2,index=0,media=disk,id=hd \
    -cdrom ./ubuntu-cloud-init.iso \
    -enable-kvm \
    -net nic -net user,hostfwd=tcp::2222-:22 \
    ${parsed_config} \
    -daemonize -display none

# Enable ssh connection to the VM
until ssh-keyscan -p 2222 -H 127.0.0.1 >> ~/.ssh/known_hosts 2>/dev/null; do
    echo "Waiting for SSH..."
    sleep 1
done
