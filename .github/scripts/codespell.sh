#!/bin/bash

set -ex

SCAN_RESULT=`codespell -H --quiet-level=3 --skip="*.h,*.cmake,*.c,*.hpp,*.cpp,*.sh,*.py,test/supp/*.supp,./.venv" --ignore-words-list="ASSER,Tne,ba,BA"`
echo -e "${SCAN_RESULT}" 
