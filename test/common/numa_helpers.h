// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#ifndef UMF_TEST_NUMA_HELPERS_H
#define UMF_TEST_NUMA_HELPERS_H 1

#include <numa.h>
#include <numaif.h>
#include <stdint.h>
#include <stdio.h>

#include "test_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

// returns the node where page starting at 'ptr' resides
int getNumaNodeByPtr(void *ptr) {
    int nodeId;
    int retm =
        get_mempolicy(&nodeId, nullptr, 0, ptr, MPOL_F_ADDR | MPOL_F_NODE);
    UT_ASSERTeq(retm, 0);
    UT_ASSERT(nodeId >= 0);

    return nodeId;
}

#ifdef __cplusplus
}
#endif

#endif /* UMF_TEST_NUMA_HELPERS_H */
