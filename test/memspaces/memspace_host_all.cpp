// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <numa.h>
#include <numaif.h>
#include <sys/mman.h>
#include <unordered_set>

#include <umf/memspace.h>

#include "memory_target_numa.h"
#include "memspace_fixtures.hpp"
#include "memspace_helpers.hpp"
#include "memspace_internal.h"
#include "numa_helpers.h"
#include "test_helpers.h"
#include "utils_sanitizers.h"

using umf_test::test;

struct memspaceHostAllTest : ::numaNodesTest {
    void SetUp() override {
        ::numaNodesTest::SetUp();

        hMemspace = umfMemspaceHostAllGet();
        ASSERT_NE(hMemspace, nullptr);
    }

    umf_const_memspace_handle_t hMemspace = nullptr;
};

struct memspaceHostAllProviderTest : ::memspaceHostAllTest {
    void SetUp() override {
        ::memspaceHostAllTest::SetUp();

        umf_result_t ret =
            umfMemoryProviderCreateFromMemspace(hMemspace, nullptr, &hProvider);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        ASSERT_NE(hProvider, nullptr);
    }

    void TearDown() override {
        ::memspaceHostAllTest::TearDown();

        umfMemoryProviderDestroy(hProvider);
    }

    umf_memory_provider_handle_t hProvider = nullptr;
};

TEST_F(numaNodesTest, memspaceGet) {
    umf_const_memspace_handle_t hMemspace = umfMemspaceHostAllGet();
    UT_ASSERTne(hMemspace, nullptr);

    // Confirm that the HOST ALL memspace is composed of all available NUMA nodes.
    UT_ASSERTeq(hMemspace->size, nodeIds.size());
    for (size_t i = 0; i < hMemspace->size; i++) {
        // NUMA memory target internally casts the config directly into priv.
        // TODO: Use the memory target API when it becomes available.
        struct umf_numa_memory_target_config_t *numaTargetCfg =
            (struct umf_numa_memory_target_config_t *)hMemspace->nodes[i]->priv;
        UT_ASSERT(std::find(nodeIds.begin(), nodeIds.end(),
                            numaTargetCfg->physical_id) != nodeIds.end());
    }
}

TEST_F(memspaceHostAllTest, providerFromHostAllMemspace) {
    umf_memory_provider_handle_t hProvider = nullptr;
    umf_result_t ret =
        umfMemoryProviderCreateFromMemspace(hMemspace, nullptr, &hProvider);
    UT_ASSERTeq(ret, UMF_RESULT_SUCCESS);
    UT_ASSERTne(hProvider, nullptr);

    umfMemoryProviderDestroy(hProvider);
}

TEST_F(memspaceHostAllProviderTest, allocFree) {
    void *ptr = nullptr;
    size_t size = SIZE_4K;
    size_t alignment = 0;

    umf_result_t ret = umfMemoryProviderAlloc(hProvider, size, alignment, &ptr);
    UT_ASSERTeq(ret, UMF_RESULT_SUCCESS);
    UT_ASSERTne(ptr, nullptr);

    memset(ptr, 0xFF, size);

    ret = umfMemoryProviderFree(hProvider, ptr, size);
    UT_ASSERTeq(ret, UMF_RESULT_SUCCESS);
}

TEST_F(memspaceHostAllProviderTest, hostAllDefaults) {
    // This testcase checks if the allocations made using the provider with
    // default parameters based on default memspace (HostAll) uses the fast,
    // default kernel path (no mbind).

    umf_const_memspace_handle_t hMemspace = umfMemspaceHostAllGet();
    UT_ASSERTne(hMemspace, nullptr);

    umf_memory_provider_handle_t hProvider = nullptr;
    umf_result_t ret = umfMemoryProviderCreateFromMemspace(
        umfMemspaceHostAllGet(), NULL, &hProvider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(hProvider, nullptr);

    // Create single allocation using the provider.
    void *ptr1 = nullptr;
    size_t size = SIZE_4K;
    size_t alignment = 0;

    ret = umfMemoryProviderAlloc(hProvider, size, alignment, &ptr1);
    UT_ASSERTeq(ret, UMF_RESULT_SUCCESS);
    UT_ASSERTne(ptr1, nullptr);
    memset(ptr1, 0xFF, size);

    // Create single allocation using mmap
    void *ptr2 = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    UT_ASSERTne(ptr2, nullptr);
    memset(ptr2, 0xFF, size);

    // Compare UMF and kernel default allocation policy
    struct bitmask *nodemask1 = numa_allocate_nodemask();
    struct bitmask *nodemask2 = numa_allocate_nodemask();
    int memMode1 = -1, memMode2 = -1;

    int ret2 = get_mempolicy(&memMode1, nodemask1->maskp, nodemask1->size, ptr1,
                             MPOL_F_ADDR);
    UT_ASSERTeq(ret2, 0);
    ret2 = get_mempolicy(&memMode2, nodemask2->maskp, nodemask2->size, ptr2,
                         MPOL_F_ADDR);
    UT_ASSERTeq(ret2, 0);
    UT_ASSERTeq(memMode1, memMode2);
    UT_ASSERTeq(nodemask1->size, nodemask2->size);
    UT_ASSERTeq(numa_bitmask_equal(nodemask1, nodemask2), 1);

    int nodeId1 = -1, nodeId2 = -1;
    ret2 = get_mempolicy(&nodeId1, nullptr, 0, ptr1, MPOL_F_ADDR | MPOL_F_NODE);
    UT_ASSERTeq(ret2, 0);
    ret2 = get_mempolicy(&nodeId2, nullptr, 0, ptr2, MPOL_F_ADDR | MPOL_F_NODE);
    UT_ASSERTeq(ret2, 0);
    UT_ASSERTeq(nodeId1, nodeId2);

    numa_free_nodemask(nodemask2);
    numa_free_nodemask(nodemask1);

    ret2 = munmap(ptr2, size);
    UT_ASSERTeq(ret2, 0);

    ret = umfMemoryProviderFree(hProvider, ptr1, size);
    UT_ASSERTeq(ret, UMF_RESULT_SUCCESS);
    umfMemoryProviderDestroy(hProvider);
}
