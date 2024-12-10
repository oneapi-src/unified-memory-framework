#!/bin/bash

OUTPUT=$1

echo "Run codespell..."
codespell --quiet-level=2 --skip "*.h,*.cmake,*.c,*.hpp,*.cpp,*.sh,*.py" -i 0 || true