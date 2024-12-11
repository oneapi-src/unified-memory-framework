#!/bin/bash
set -ex

OUTPUT=$1
# codespell --quiet-level=2 --skip "*.h,*.cmake,*.c,*.hpp,*.cpp,*.sh,*.py,test/supp/*.supp" -i 0 -L "ASSER,Tne,ba,BA"

SCAN_RESULT=`codespell --quiet-level=3 --skip "*.h,*.cmake,*.c,*.hpp,*.cpp,*.sh,*.py,test/supp/*.supp" -i 0 -L "ASSER,Tne,ba,BA" -H --count`
echo -e "${SCAN_RESULT}" 
echo -e "${SCAN_RESULT}" > ${OUTPUT}
cat ${OUTPUT}

if [[ ! -z ${SCAN_RESULT} ]]; then
    exit 1
fi
