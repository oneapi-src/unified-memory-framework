// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#ifndef UMF_TEST_MEMSPACE_HELPERS_HPP
#define UMF_TEST_MEMSPACE_HELPERS_HPP

#include "base.hpp"
#include "memspace_internal.h"
#include "test_helpers.h"

#include <numa.h>
#include <numaif.h>
#include <umf/providers/provider_os_memory.h>

#define SIZE_4K (4096UL)
#define SIZE_4M (SIZE_4K * 1024UL)

///
/// @brief Retrieves the memory policy information for \p ptr.
/// @param ptr allocation pointer.
/// @param maxNodeId maximum node id.
/// @param mode [out] memory policy.
/// @param boundNodeIds [out] node ids associated with the policy.
/// @param allocNodeId [out] id of the node that allocated the memory.
///
void getAllocationPolicy(void *ptr, unsigned long maxNodeId, int &mode,
                         std::vector<size_t> &boundNodeIds,
                         size_t &allocNodeId) {
    const static unsigned bitsPerUlong = sizeof(unsigned long) * 8;

    const unsigned nrUlongs = (maxNodeId + bitsPerUlong) / bitsPerUlong;
    std::vector<unsigned long> memNodeMasks(nrUlongs, 0);

    int memMode = -1;
    // Get policy and the nodes associated with this policy.
    int ret = get_mempolicy(&memMode, memNodeMasks.data(),
                            nrUlongs * bitsPerUlong, ptr, MPOL_F_ADDR);
    ASSERT_EQ(ret, 0);
    mode = memMode;

    ASSERT_EQ(boundNodeIds.size(), 0);
    for (size_t i = 0; i <= maxNodeId; i++) {
        const size_t memNodeMaskIdx = ((i + bitsPerUlong) / bitsPerUlong) - 1;
        const auto &memNodeMask = memNodeMasks.at(memNodeMaskIdx);

        if (memNodeMask && (1UL << (i % bitsPerUlong))) {
            boundNodeIds.emplace_back(i);
        }
    }

    // Get the node that allocated the memory at 'ptr'.
    int nodeId = -1;
    ret = get_mempolicy(&nodeId, nullptr, 0, ptr, MPOL_F_ADDR | MPOL_F_NODE);
    ASSERT_EQ(ret, 0);
    allocNodeId = static_cast<size_t>(nodeId);
}

#endif /* UMF_TEST_MEMSPACE_HELPERS_HPP */
