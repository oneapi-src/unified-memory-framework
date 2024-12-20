#!/bin/sh -e
# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# You can add an exception file
grep -v -E -e 'src/uthash/.*' \
           -e 'benchmark/ubench.h' \
           -e 'include/umf/proxy_lib_new_delete.h' \
           -e 'scripts/docs_config/conf.py' \
           -e 'src/uthash/utlist.h' \
           -e 'src/uthash/uthash.h' \
           -e '\.yml$'\
           -e '\.clang-format$' \
           -e '\.md$' \
           -e '\.cmake-format$' \
           -e 'CODEOWNERS$' \
           -e 'scripts/assets/images/.*' \
           -e 'scripts/docs_config/.*' \
           -e '\.xml$' \
           -e '\.txt$' \
           -e 'test/supp/.*' \
           -e '\.json$' \
           -e 'LICENSE.TXT' \
           -e '.github/workflows/.spellcheck-conf.toml' \
           -e '.gitignore' \
           -e '.mailmap' \
           -e '.trivyignore' \
           -e 'ChangeLog' \
           -e '\.cmake.in$' \
           -e '\.patch$'
