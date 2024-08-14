// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#ifndef UMF_TEST_NUMA_HELPERS_HPP
#define UMF_TEST_NUMA_HELPERS_HPP 1

#include <gtest/gtest.h>
#include <numa.h>
#include <numaif.h>
#include <stdint.h>
#include <stdio.h>

#include "test_helpers.h"

// returns the node where page starting at 'ptr' resides
static inline void getNumaNodeByPtr(void *ptr, int *node) {
    int nodeId;
    int ret =
        get_mempolicy(&nodeId, nullptr, 0, ptr, MPOL_F_ADDR | MPOL_F_NODE);

    ASSERT_EQ(ret, 0) << "get_mempolicy failed";
    ASSERT_GE(nodeId, 0)
        << "get_mempolicy returned nodeId < 0 - should never happen";

    *node = nodeId;
}

static inline void _assertNode(void *ptr, int nodeId, bool fatal) {
    int node = -1;

    getNumaNodeByPtr(ptr, &node);
    if (testing::Test::HasFatalFailure()) {
        return;
    }
    if (fatal) {
        ASSERT_EQ(nodeId, node);
    } else {
        EXPECT_EQ(nodeId, node);
    }
}

//Asserts that given nodeId is equal to the node where given ptr resides
#define ASSERT_NODE_EQ(ptr, nodeId)                                            \
    ASSERT_NO_FATAL_FAILURE(_assertNode(ptr, nodeId, true))

#define EXPECT_NODE_EQ(ptr, nodeId)                                            \
    ASSERT_NO_FATAL_FAILURE(_assertNode(ptr, nodeId, false))

#endif /* UMF_TEST_NUMA_HELPERS_HPP */
