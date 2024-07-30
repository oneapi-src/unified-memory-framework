#  Copyright (C) 2024 Intel Corporation
#
#  Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
#  SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# A script testing if all UMF files are installed and uninstalled correctly

import argparse
import difflib
from packaging.version import Version
from pathlib import Path
import platform
import subprocess  # nosec B404
import sys
from typing import List


class UmfInstaller:
    """
    Manages the installation and uninstallation of the UMF.

    Attributes:
    workspace_dir (Path): The main directory of UMF repository
    build_dir (Path): Path to the build directory
    install_dir (Path): Path to the installation directory, it has to be empty
    build_type (str): Debug or Release build type passed to the script
    shared_library (bool): Determines if the UMF was built as a shared library
    proxy (bool): Determines whether the proxy library should be built together with the UMF library
    pools (List[str]): A list of enabled pools during the UMF compilation
    umf_version (Version): UMF version currently being built and installed
    match_list (List[str]): A list of relative paths of files that should be installed
    """

    def __init__(
        self,
        workspace_dir: Path,
        build_dir: Path,
        install_dir: Path,
        build_type: str,
        shared_library: bool,
        proxy: bool,
        pools: List[str],
        umf_version: Version,
    ):
        self.workspace_dir = workspace_dir
        self.build_dir = build_dir
        self.install_dir = install_dir
        self.build_type = build_type
        self.shared_library = shared_library
        self.proxy = proxy
        self.pools = pools
        self.umf_version = umf_version
        self.match_list = self._create_match_list()

    def _create_match_list(self) -> List[str]:
        """
        Defines a list of relative paths to files that should be installed.
        This list is used to validate the installation.
        """

        lib_ext_static = ""
        lib_ext_shared = ""
        lib_prefix = ""
        if platform.system() == "Windows":
            lib_ext_static = "lib"
            lib_ext_shared = "lib"
        elif platform.system() == "Linux":
            lib_ext_static = "a"
            lib_ext_shared = "so"
            lib_prefix = "lib"
        else:  # MacOS
            lib_ext_static = "a"
            lib_ext_shared = "dylib"
            lib_prefix = "lib"

        bin = []
        if platform.system() == "Windows" and (self.shared_library or self.proxy):
            bin.append("bin")
            if self.shared_library:
                bin.append("bin/umf.dll")
            if self.proxy:
                bin.append("bin/umf_proxy.dll")

        include_dir = Path(self.workspace_dir, "include")
        include = [
            str(entry.relative_to(self.workspace_dir))
            for entry in sorted(include_dir.rglob("*"), key=lambda x: str(x).casefold())
        ]
        include.insert(0, "include")

        lib = [
            "lib",
            "lib/cmake",
            "lib/cmake/umf",
            "lib/cmake/umf/umf-config-version.cmake",
            "lib/cmake/umf/umf-config.cmake",
            f"lib/cmake/umf/umf-targets-{self.build_type}.cmake",
            "lib/cmake/umf/umf-targets.cmake",
        ]
        for pool in self.pools:
            lib.append(f"lib/{lib_prefix}{pool}.{lib_ext_static}")
        if self.shared_library:
            lib.append(f"lib/{lib_prefix}umf.{lib_ext_shared}")

            if platform.system() == "Linux":
                lib.append(
                    f"lib/{lib_prefix}umf.{lib_ext_shared}.{self.umf_version.major}"
                )
                lib.append(f"lib/{lib_prefix}umf.{lib_ext_shared}.{self.umf_version}")
            elif platform.system() == "Darwin":  # MacOS
                lib.append(
                    f"lib/{lib_prefix}umf.{self.umf_version.major}.{lib_ext_shared}"
                )
                lib.append(f"lib/{lib_prefix}umf.{self.umf_version}.{lib_ext_shared}")
        else:
            lib.append(f"lib/{lib_prefix}umf.{lib_ext_static}")

        if self.proxy:
            lib.append(f"lib/{lib_prefix}umf_proxy.{lib_ext_shared}")

            if platform.system() == "Linux":
                lib.append(
                    f"lib/{lib_prefix}umf_proxy.{lib_ext_shared}.{self.umf_version.major}"
                )
            elif platform.system() == "Darwin":  # MacOS
                lib.append(
                    f"lib/{lib_prefix}umf_proxy.{self.umf_version.major}.{lib_ext_shared}"
                )

        share = []
        share = [
            "share",
            "share/doc",
            "share/doc/umf",
        ]

        examples_dir = Path(self.workspace_dir, "examples")
        examples_files = [
            str(entry.relative_to(self.workspace_dir))
            for entry in sorted(
                examples_dir.rglob("*"), key=lambda x: str(x).casefold()
            )
        ]
        examples = [f"share/doc/umf/" + file for file in examples_files]
        examples = sorted(examples)
        examples.insert(0, "share/doc/umf/examples")
        share.extend(examples)
        share.append("share/doc/umf/LICENSE.TXT")
        share.append("share/doc/umf/licensing")
        share.append("share/doc/umf/licensing/third-party-programs.txt")

        all_files = bin + include + lib + share
        if platform.system() == "Windows":
            all_files = [file.replace("/", "\\") for file in all_files]

        return all_files

    def install_umf(self) -> None:
        """
        Runs the UMF installation
        """

        try:
            self.install_dir.mkdir(parents=True)
        except FileExistsError:
            if list(self.install_dir.iterdir()):
                sys.exit(
                    f"Error: Installation directory '{self.install_dir}' is not empty"
                )

        install_cmd = f"cmake --install {self.build_dir} --config {self.build_type.title()} --prefix {self.install_dir}"
        try:
            subprocess.run(install_cmd.split()).check_returncode()  # nosec B603
        except subprocess.CalledProcessError:
            sys.exit(f"Error: UMF installation command '{install_cmd}' failed")

    def validate_installed_files(self) -> None:
        """
        Validates the UMF installation against the match list
        """

        installed_files = [
            str(entry.relative_to(self.install_dir))
            for entry in sorted(
                self.install_dir.rglob("*"), key=lambda x: str(x).casefold()
            )
        ]

        expected_files = [
            str(entry)
            for entry in sorted(self.match_list, key=lambda x: str(x).casefold())
        ]

        diff = list(
            difflib.unified_diff(
                expected_files,
                installed_files,
                fromfile="Expected files",
                tofile="Installed files",
                lineterm="",
            )
        )
        if len(diff):
            for line in diff:
                print(line)
            sys.exit("Installation test - FAILED")

    def uninstall_umf(self) -> None:
        """
        Run the UMF uninstallation CMake target.
        It removes all installed files leaving empty directories
        """
        uninstall_cmd = f"cmake --build {self.build_dir} --target uninstall"
        try:
            subprocess.run(uninstall_cmd.split()).check_returncode()  # nosec B603
        except subprocess.CalledProcessError:
            sys.exit(f"Error: UMF uninstallation command '{uninstall_cmd}' failed")

    def validate_uninstallation_leftovers(self) -> None:
        """
        Validates the UMF uninstallation - verifies that no files are left,
        only empty directories.
        """

        files_left = [file for file in self.install_dir.rglob("*") if file.is_file()]

        if len(files_left):
            print("These files should be removed:", flush=True)
            for file in files_left:
                print(file)
            sys.exit("Uninstallation test - FAILED")


class UmfInstallationTester:
    """
    Parses script arguments and runs the tests

    Attributes:
    parser (argparse.ArgumentParser): an argument parser
    args (argparse.Namespace): Values of arguments passed to the script
    """

    def __init__(self) -> None:
        self.parser = argparse.ArgumentParser(
            description="A script testing if all UMF files are installed and uninstalled correctly"
        )
        self.args = self.parse_arguments()

    def parse_arguments(self) -> argparse.Namespace:
        """
        Parses arguments passed to the script
        """

        self.parser.add_argument(
            "--build-dir",
            default="build",
            help="Existing UMF build directory, default: build",
        )
        self.parser.add_argument(
            "--install-dir",
            default="build/install-dir",
            help="Empty directory where UMF will be installed, default: build/install-dir",
        )
        self.parser.add_argument(
            "--build-type",
            type=str.lower,
            choices=["debug", "release"],
            required=True,
            help="Build type used for compilation",
        )
        self.parser.add_argument(
            "--shared-library",
            action="store_true",
            help="Add this argument if the UMF was built as a shared library",
        )
        self.parser.add_argument(
            "--proxy",
            action="store_true",
            help="Add this argument if the proxy library should be built together with the UMF library",
        )
        self.parser.add_argument(
            "--disjoint-pool",
            action="store_true",
            help="Add this argument if the UMF was built with Disjoint Pool enabled",
        )
        self.parser.add_argument(
            "--jemalloc-pool",
            action="store_true",
            help="Add this argument if the UMF was built with Jemalloc Pool enabled",
        )
        self.parser.add_argument(
            "--umf-version",
            action="store",
            help="Current version of the UMF, e.g. 1.0.0",
        )
        return self.parser.parse_args()

    def run(self) -> None:
        """
        Runs the installation test
        """

        workspace_dir = Path(__file__).resolve().parents[1]
        build_dir = Path(workspace_dir, self.args.build_dir)
        install_dir = Path(workspace_dir, self.args.install_dir)
        pools = []
        if self.args.disjoint_pool:
            pools.append("disjoint_pool")
        if self.args.jemalloc_pool:
            pools.append("jemalloc_pool")

        umf_version = Version(self.args.umf_version)

        umf_installer = UmfInstaller(
            workspace_dir,
            build_dir,
            install_dir,
            self.args.build_type,
            self.args.shared_library,
            self.args.proxy,
            pools,
            umf_version,
        )

        print("Installation test - BEGIN", flush=True)

        umf_installer.install_umf()
        umf_installer.validate_installed_files()

        print("Installation test - PASSED", flush=True)

        print("Uninstallation test - BEGIN", flush=True)

        umf_installer.uninstall_umf()
        umf_installer.validate_uninstallation_leftovers()

        print("Uninstallation test - PASSED", flush=True)


if __name__ == "__main__":
    tester = UmfInstallationTester()
    tester.run()
