#!/bin/sh -e
# Copyright (C) 2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# You can add an exception file
# list for license and copyright check
grep -v -E -e 'benchmark/ubench.h' \
           -e 'ChangeLog' \
           -e 'CODEOWNERS$' \
           -e 'docs/assets/.*' \
           -e 'docs/config/conf.py' \
           -e 'docs/config/Doxyfile' \
           -e 'include/umf/proxy_lib_new_delete.h' \
           -e 'LICENSE.TXT' \
           -e 'licensing/third-party-programs.txt' \
           -e 'scripts/assets/images/.*' \
           -e 'scripts/qemu/requirements.txt' \
           -e 'src/uthash/.*' \
           -e 'src/uthash/utlist.h' \
           -e 'src/uthash/uthash.h' \
           -e 'test/ctl/config.txt' \
           -e 'test/supp/.*' \
           -e 'third_party/requirements.txt' \
           -e '.clang-format$' \
           -e '.cmake-format$' \
           -e '.cmake.in$' \
           -e '.gitignore' \
           -e '.json$' \
           -e '.mailmap' \
           -e '.md$' \
           -e '.patch$' \
           -e '.rst$' \
           -e '.spellcheck-conf.toml' \
           -e '.trivyignore' \
           -e '.xml$' \
           -e '.yml$'
