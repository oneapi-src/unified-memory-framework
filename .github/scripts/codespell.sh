#!/bin/bash
set -ex

# OUTPUT=$1

SCAN_RESULT=`codespell -H --quiet-level=3 --skip="*.h,*.cmake,*.c,*.hpp,*.cpp,*.sh,*.py,test/supp/*.supp,./.venv" --ignore-words-list="ASSER,Tne,ba,BA" CODE_OF_CONDUCT.md`
echo -e "${SCAN_RESULT}" 
# echo -e "${SCAN_RESULT}" > ${OUTPUT}
# cat ${OUTPUT}

if [[ ! -z ${SCAN_RESULT} ]]; then
    exit 1
fi
