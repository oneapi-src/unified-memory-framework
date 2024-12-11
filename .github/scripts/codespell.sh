#!/bin/bash

echo "Run codespell..."
codespell --quiet-level=2 --skip "*.h,*.cmake,*.c,*.hpp,*.cpp,*.sh,*.py,test/supp/*.supp" -i 0 -L "ASSER,Tne,ba,BA" || true
