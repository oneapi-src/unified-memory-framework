"""
 Copyright (C) 2023-2024 Intel Corporation

 Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""

import re
import subprocess  # nosec
import sys
import collections
import os
import psutil
import shutil

# This script parses the topology xml file and returns QEMU arguments.
#
# Before running this script:
# - install python deps for this script: pip install -r requirements.txt
# - install 'libvirt-clients' package (for virsh)
#
# Enable verbose mode by setting environment variable: ENABLE_VERBOSE=1

TopologyCfg = collections.namedtuple(
    "TopologyCfg", ["name", "hmat", "cpu_model", "cpu_options", "mem_options"]
)

verbose_mode = False


def enable_verbose():
    """
    Check if env var ENABLE_VERBOSE is set and enable verbose mode
    """
    global verbose_mode
    verbose_mode = os.getenv("ENABLE_VERBOSE", False)


def parse_topology_xml(tpg_file_name: str) -> TopologyCfg:
    """
    Parse topology xml file
    """
    try:
        virsh_path = shutil.which("virsh")
        if virsh_path is None:
            raise Exception("virsh not found in PATH")

        result = subprocess.run(  # nosec
            [virsh_path, "domxml-to-native", "qemu-argv", tpg_file_name],
            stdout=subprocess.PIPE,
            shell=False,
        )
        result.check_returncode()
        libvirt_args = result.stdout.decode("utf-8").strip()

        if verbose_mode != False:
            print(f"\nFull libvirt_args: {libvirt_args}\n")

        hmat_search = re.search(r"hmat=(\w+)", libvirt_args)
        tpg_cfg = {
            "name": re.search(r"guest=(\w+)", libvirt_args).group(1),
            "hmat": hmat_search.group(0) if hmat_search else "hmat=off",
            "cpu_model": re.search(r"cpu (\S+)", libvirt_args).group(1),
            "cpu_options": re.search("(?=-smp)(.*)threads=[0-9]+", libvirt_args).group(
                0
            ),
            "mem_options": re.search(
                r"-object '{\"qom-type\":\"memory-backend-ram\".*(?=-uuid)",
                libvirt_args,
            ).group(0),
        }

        if verbose_mode != False:
            print(f"Name: {tpg_cfg['cpu_model']}")
            print(f"HMAT: {tpg_cfg['hmat']}")
            print(f"CPU_MODEL: {tpg_cfg['cpu_model']}")
            print(f"CPU_OPTIONS: {tpg_cfg['cpu_options']}")
            print(f"MEM_OPTIONS: {tpg_cfg['mem_options']}")

        tpg = TopologyCfg(**tpg_cfg)
    except subprocess.CalledProcessError:
        sys.exit(f"\n XML file: {tpg_file_name} error in virsh parsing")
    except Exception:
        sys.exit(f"\n Provided file ({tpg_file_name}) is missing or missing virsh.")
    return tpg


def get_qemu_args(tpg_file_name: str) -> str:
    """
    Get QEMU arguments from topology xml file
    """
    tpg = parse_topology_xml(tpg_file_name)
    qemu_args = (
        f"-machine q35,usb=off,{tpg.hmat} -name {tpg.name} "
        f"{calculate_memory(tpg)} -cpu {tpg.cpu_model} {tpg.cpu_options} {tpg.mem_options}"
    )
    return qemu_args


def calculate_memory(tpg: TopologyCfg) -> str:
    """
    Total memory required by given QEMU config
    """
    if tpg.mem_options:
        mem_needed = 0
        all_sizes = re.findall(r'size":(\d+)', tpg.mem_options)
        for single_size in all_sizes:
            mem_needed += int(single_size)

        mem = psutil.virtual_memory()
        if mem_needed >= mem.total:
            raise MemoryHostException(mem.total, mem_needed, tpg.name)
        return f"-m {mem_needed/1024/1024}M"
    else:
        return "-m 2G"


if __name__ == "__main__":
    enable_verbose()

    if len(sys.argv) > 1:
        tpg_file_name = sys.argv[1]
    else:
        sys.exit(f"\n Usage: {sys.argv[0]} <tpg_file_name>")

    # Print QEMU arguments as a result of this script
    print(get_qemu_args(tpg_file_name))
