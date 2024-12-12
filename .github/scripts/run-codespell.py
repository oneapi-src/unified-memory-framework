"""
 Copyright (C) 2024 Intel Corporation

 Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""

import subprocess  # nosec B404
import logging
import sys

logging.basicConfig(
    level=logging.INFO, format="[%(levelname)s]: [%(asctime)s] %(message)s"
)


def codespell_scan():
    try:
        codespell_result = subprocess.run(  # nosec
            [
                "codespell",
                "-H",
                "--quiet-level=3",
                "--skip=./.git,./.venv,./.github/workflows/.spellcheck-conf.toml",
            ],
            text=True,
            stdout=subprocess.PIPE,
        )
        if codespell_result.returncode != 0:
            for line in codespell_result.stdout.splitlines():
                logging.error(line.strip())
            sys.exit(1)
        else:
            logging.info("No spelling errors found")
    except subprocess.CalledProcessError as ex:
        logging.error(ex)
        sys.exit(1)


codespell_scan()
