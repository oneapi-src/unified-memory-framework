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
    int ret = get_mempolicy(node, nullptr, 0, ptr, MPOL_F_ADDR | MPOL_F_NODE);

    ASSERT_EQ(ret, 0) << "get_mempolicy failed";
    ASSERT_GE(*node, 0)
        << "get_mempolicy returned nodeId < 0 - should never happen";
}

// returns the mode in which page starting at 'ptr' is bound
static inline void getBindModeByPtr(void *ptr, int *mode) {
    int ret = get_mempolicy(mode, nullptr, 0, ptr, MPOL_F_ADDR);

    ASSERT_EQ(ret, 0) << "get_mempolicy failed";
}

// returns the mask in which page starting at 'ptr' is bound
static inline void getBindMaskByPtr(void *ptr, struct bitmask *mask) {
    int ret = get_mempolicy(nullptr, mask->maskp, mask->size, ptr, MPOL_F_ADDR);

    ASSERT_EQ(ret, 0) << "get_mempolicy failed";
}

// Internal do not use directly
#define _CUSTOMIZABLE_ASSERT(expr, fatal, eq)                                  \
    do {                                                                       \
        if (fatal) {                                                           \
            if (eq) {                                                          \
                ASSERT_TRUE(expr);                                             \
            } else {                                                           \
                ASSERT_FALSE(expr);                                            \
            }                                                                  \
        } else {                                                               \
            if (eq) {                                                          \
                EXPECT_TRUE(expr);                                             \
            } else {                                                           \
                EXPECT_FALSE(expr);                                            \
            }                                                                  \
        }                                                                      \
    } while (0)

// Internal do not use directly
static inline void _assertNode(void *ptr, int expected_node, bool fatal,
                               bool eq) {
    int node;

    getNumaNodeByPtr(ptr, &node);
    if (testing::Test::HasFatalFailure()) {
        return;
    }

    _CUSTOMIZABLE_ASSERT(node == expected_node, fatal, eq);
}

// Internal do not use directly
static inline void _assertNode(void *ptr, void *ptr2, bool fatal, bool eq) {
    int node, node2;

    getNumaNodeByPtr(ptr, &node);
    getNumaNodeByPtr(ptr2, &node2);
    if (testing::Test::HasFatalFailure()) {
        return;
    }

    _CUSTOMIZABLE_ASSERT(node == node2, fatal, eq);
}

// Internal do not use directly
static inline void _assertBindMode(void *ptr, int expected_mode, bool fatal,
                                   bool eq) {
    int mode;

    getBindModeByPtr(ptr, &mode);
    if (testing::Test::HasFatalFailure()) {
        return;
    }

    _CUSTOMIZABLE_ASSERT(mode == expected_mode, fatal, eq);
}

static inline void _assertBindMode(void *ptr, void *ptr2, bool fatal, bool eq) {
    int mode, mode2;

    getBindModeByPtr(ptr, &mode);
    getBindModeByPtr(ptr2, &mode2);
    if (testing::Test::HasFatalFailure()) {
        return;
    }

    _CUSTOMIZABLE_ASSERT(mode == mode2, fatal, eq);
}

// Internal do not use directly
static inline void _assertBindMask(void *ptr, struct bitmask *expected_mask,
                                   bool fatal, bool eq) {
    struct bitmask *mask = numa_allocate_nodemask();
    ASSERT_NE(mask, nullptr) << "numa_allocate_nodemask failed";

    getBindMaskByPtr(ptr, mask);
    if (testing::Test::HasFatalFailure()) {
        return;
    }

    _CUSTOMIZABLE_ASSERT(numa_bitmask_equal(mask, expected_mask), fatal, eq);

    numa_free_nodemask(mask);
}

// Internal do not use directly
static inline void _assertBindMask(void *ptr, void *ptr2, bool fatal, bool eq) {
    struct bitmask *mask = numa_allocate_nodemask();
    ASSERT_NE(mask, nullptr) << "numa_allocate_nodemask failed";

    getBindMaskByPtr(ptr, mask);

    struct bitmask *mask2 = numa_allocate_nodemask();
    ASSERT_NE(mask2, nullptr) << "numa_allocate_nodemask failed";

    getBindMaskByPtr(ptr2, mask2);

    if (testing::Test::HasFatalFailure()) {
        return;
    }

    _CUSTOMIZABLE_ASSERT(numa_bitmask_equal(mask, mask2), fatal, eq);

    numa_free_nodemask(mask);
    numa_free_nodemask(mask2);
}

// Asserts that a memory page starting at 'ptr' is on the expected NUMA node,
// The target can be either a specific node or another pointer, in which case we compare nodes of both ptr.
#define ASSERT_NODE_EQ(ptr, target)                                            \
    ASSERT_NO_FATAL_FAILURE(_assertNode(ptr, target, true, true))

// Asserts that a memory page starting at 'ptr' is not on the expected NUMA node,
// The target can be either a specific node or another pointer, in which case we compare nodes of both ptr.
#define ASSERT_NODE_NE(ptr, target)                                            \
    ASSERT_NO_FATAL_FAILURE(_assertNode(ptr, target, true, false))

// Expects that a memory page starting at 'ptr' is on the expected NUMA node,
// Target can be either a node id or another pointer, in which case we compare nodes of both ptr.
#define EXPECT_NODE_EQ(ptr, target)                                            \
    ASSERT_NO_FATAL_FAILURE(_assertNode(ptr, target, false, true))

// Expects that a memory page starting at 'ptr' is not on the expected NUMA node,
// Target can be either a node id or another pointer, in which case we compare nodes of both ptr.
#define EXPECT_NODE_NE(ptr, target)                                            \
    ASSERT_NO_FATAL_FAILURE(_assertNode(ptr, target, false, false))

// Asserts that a memory page starting at 'ptr' is bound in the expected memory binding mode.
// The target can be either a specific mode or another pointer, in which case we compare the modes of both ptr.
#define ASSERT_BIND_MODE_EQ(ptr, target)                                       \
    ASSERT_NO_FATAL_FAILURE(_assertBindMode(ptr, target, true, true))
// Asserts that a memory page starting at 'ptr' is not bound in the expected memory binding mode.
// The target can be either a specific mode or another pointer, in which case we compare the modes of both ptr.
#define ASSERT_BIND_MODE_NE(ptr, target)                                       \
    ASSERT_NO_FATAL_FAILURE(_assertBindMode(ptr, target, true, false))

// Expects that a memory page starting at 'ptr' is bound in the expected memory binding mode.
// The target can be either a specific mode or another pointer, in which case we compare the modes of both ptr.
#define EXPECT_BIND_MODE_EQ(ptr, target)                                       \
    ASSERT_NO_FATAL_FAILURE(_assertBindMode(ptr, target, false, true))

// Expects that a memory page starting at 'ptr' is not bound in the expected memory binding mode.
// The target can be either a specific mode or another pointer, in which case we compare the modes of both ptr.
#define EXPECT_BIND_MODE_NE(ptr, target)                                       \
    ASSERT_NO_FATAL_FAILURE(_assertBindMode(ptr, target, false, false))

// Asserts that the memory binding mask for the page starting at 'ptr' matches the expected mask.
// The target can be either a bitmask or another pointer, in which case we compare the masks of both ptr.
#define ASSERT_BIND_MASK_EQ(ptr, target)                                       \
    ASSERT_NO_FATAL_FAILURE(_assertBindMask(ptr, target, true, true))

// Asserts that the memory binding mask for the page starting at 'ptr' does not match the expected mask.
// The target can be either a bitmask or another pointer, in which case we compare the masks of both ptr.
#define ASSERT_BIND_MASK_NE(ptr, target)                                       \
    ASSERT_NO_FATAL_FAILURE(_assertBindMask(ptr, target, true, false))

// Expects that the memory binding mask for the page starting at 'ptr' matches the expected mask.
// The target can be either a bitmask or another pointer, in which case we compare the masks of both ptr.
#define EXPECT_BIND_MASK_EQ(ptr, target)                                       \
    ASSERT_NO_FATAL_FAILURE(_assertBindMask(ptr, target, false, true))

// Expects that the memory binding mask for the page starting at 'ptr' does not match the expected mask.
// The target can be either a bitmask or another pointer, in which case we compare the masks of both ptr.
#define EXPECT_BIND_MASK_NE(ptr, target)                                       \
    ASSERT_NO_FATAL_FAILURE(_assertBindMask(ptr, target, false, false))

#endif /* UMF_TEST_NUMA_HELPERS_HPP */
