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

    umf_memspace_handle_t hMemspace = nullptr;
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
    umf_memspace_handle_t hMemspace = umfMemspaceHostAllGet();
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

    umf_memspace_handle_t hMemspace = umfMemspaceHostAllGet();
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

TEST_F(memspaceHostAllProviderTest, allocsSpreadAcrossAllNumaNodes) {
    // This testcase is unsuitable for TSan.
#ifdef __SANITIZE_THREAD__
    GTEST_SKIP();
#endif

    // Arbitrary allocation size, should be big enough to avoid unnecessarily
    // prolonging the test execution.
    size_t size = SIZE_4M;
    size_t alignment = 0;
    // Unallocated memory space that has to be left in an attempt to avoid OOM
    // killer - 512MB.
    size_t remainingSpace = SIZE_4M * 128;

    long long numaCombinedFreeSize = 0;
    // Gather free size of all numa nodes.
    for (auto &id : nodeIds) {
        long long numaFreeSize = 0;
        long long numaSize = numa_node_size64(id, &numaFreeSize);
        UT_ASSERTne(numaSize, -1);
        UT_ASSERT(numaFreeSize >= (long long)(remainingSpace + size));

        numaCombinedFreeSize += numaFreeSize;
    }

    umf_result_t umf_ret = UMF_RESULT_SUCCESS;
    // Create allocations until all the NUMA nodes until there's space only for
    // one allocation.
    std::vector<void *> allocs;
    std::unordered_set<size_t> allocNodeIds;
    while (numaCombinedFreeSize >= (long long)(remainingSpace + size)) {
        void *ptr = nullptr;
        umf_ret = umfMemoryProviderAlloc(hProvider, size, alignment, &ptr);
        if (umf_ret != UMF_RESULT_SUCCESS) {
            UT_ASSERTeq(umf_ret, UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC);
            const char *msg = nullptr;
            int32_t err = 0;
            umfMemoryProviderGetLastNativeError(hProvider, &msg, &err);
            // In this scenario, 'UMF_OS_RESULT_ERROR_ALLOC_FAILED' indicates OOM.
            UT_ASSERTeq(err, UMF_OS_RESULT_ERROR_ALLOC_FAILED);
            break;
        }

        UT_ASSERTne(ptr, nullptr);
        // Access the allocation, so that all the pages associated with it are
        // allocated on available NUMA nodes.
        memset(ptr, 0xFF, size);

        int mode = -1;
        std::vector<size_t> boundNodeIds;
        size_t allocNodeId = SIZE_MAX;
        getAllocationPolicy(ptr, maxNodeId, mode, boundNodeIds, allocNodeId);

        // In case of 'HOST ALL' memspace, the default set of nodes (that
        // contains all available nodes) is used but get_mempolicy() would
        // return an empty set of nodes.
        UT_ASSERTeq(mode, MPOL_DEFAULT);
        UT_ASSERTeq(boundNodeIds.size(), 0);

        // Confirm that the memory is allocated on one of the nodes in
        // 'HOST ALL' memspace.
        auto it = std::find(nodeIds.begin(), nodeIds.end(), allocNodeId);
        UT_ASSERT(it != nodeIds.end());

        allocs.push_back(ptr);
        allocNodeIds.insert(allocNodeId);

        numaCombinedFreeSize -= size;
    }

    UT_ASSERT(allocs.size() >= nodeIds.size());
    for (auto &ptr : allocs) {
        umf_ret = umfMemoryProviderFree(hProvider, ptr, size);
        UT_ASSERTeq(umf_ret, UMF_RESULT_SUCCESS);
    }

    // TODO: we want to enable this check only when tests are running under QEMU.
    // Otherwise it might sporadically fail on a real system where other processes
    // occupied all memory from a aparticular NUMA node.
#if 0
    // Confirm that all the NUMA nodes bound to 'HOST ALL' memspace were exhausted.
    for (auto &id : nodeIds) {
        auto it = std::find(allocNodeIds.begin(), allocNodeIds.end(), id);
        UT_ASSERT(it != allocNodeIds.end());
    }
#endif
}
