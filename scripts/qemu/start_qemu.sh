#!/bin/bash
# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set -x
set -e

config_file=$1

python3 scripts/qemu/qemu_config.py $config_file

if grep -q '<interconnects>' "$config_file"; then
    hmat="on"
else
    hmat="off"
fi

sudo qemu-system-x86_64 \
    -drive file=./ubuntu-23.04-server-cloudimg-amd64.img,format=qcow2,index=0,media=disk,id=hd \
    -cdrom ./ubuntu-cloud-init.iso \
    -machine q35,usb=off,hmat=$hmat \
    -enable-kvm \
    -net nic -net user,hostfwd=tcp::2222-:22 \
    $(python3 scripts/qemu/qemu_config.py $config_file | sed s/''\''/'/g) \
    -daemonize -display none

until ssh-keyscan -p 2222 -H 127.0.0.1 >> ~/.ssh/known_hosts 2>/dev/null; do
    echo "Waiting for SSH..."
    sleep 1
done
