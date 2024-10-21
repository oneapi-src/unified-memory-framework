// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <numa.h>
#include <numaif.h>
#include <sys/mman.h>
#include <unordered_set>

#include <umf/memspace.h>

#include "memspace_fixtures.hpp"
#include "memspace_helpers.hpp"
#include "memspace_internal.h"
#include "memtarget_numa.h"
#include "numa_helpers.hpp"
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
    ASSERT_NE(hMemspace, nullptr);

    // Confirm that the HOST ALL memspace is composed of all available NUMA nodes.
    ASSERT_EQ(hMemspace->size, nodeIds.size());
    for (size_t i = 0; i < hMemspace->size; i++) {
        // NUMA memory target internally casts the config directly into priv.
        // TODO: Use the memory target API when it becomes available.
        struct umf_numa_memtarget_config_t *numaTargetCfg =
            (struct umf_numa_memtarget_config_t *)hMemspace->nodes[i]->priv;
        ASSERT_NE(std::find(nodeIds.begin(), nodeIds.end(),
                            numaTargetCfg->physical_id),
                  nodeIds.end());
    }
}

TEST_F(memspaceHostAllTest, providerFromHostAllMemspace) {
    umf_memory_provider_handle_t hProvider = nullptr;
    umf_result_t ret =
        umfMemoryProviderCreateFromMemspace(hMemspace, nullptr, &hProvider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(hProvider, nullptr);

    umfMemoryProviderDestroy(hProvider);
}

TEST_F(memspaceHostAllProviderTest, allocFree) {
    void *ptr = nullptr;
    size_t size = SIZE_4K;
    size_t alignment = 0;

    umf_result_t ret = umfMemoryProviderAlloc(hProvider, size, alignment, &ptr);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    memset(ptr, 0xFF, size);

    ret = umfMemoryProviderFree(hProvider, ptr, size);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
}

TEST_F(memspaceHostAllProviderTest, hostAllDefaults) {
    // This testcase checks if the allocations made using the provider with
    // default parameters based on default memspace (HostAll) uses the fast,
    // default kernel path (no mbind).

    umf_const_memspace_handle_t hMemspace = umfMemspaceHostAllGet();
    ASSERT_NE(hMemspace, nullptr);

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
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr1, nullptr);
    memset(ptr1, 0xFF, size);

    // Create single allocation using mmap
    void *ptr2 = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(ptr2, nullptr);
    memset(ptr2, 0xFF, size);

    EXPECT_NODE_EQ(ptr1, ptr2);
    EXPECT_BIND_MODE_EQ(ptr1, ptr2);
    EXPECT_BIND_MASK_EQ(ptr1, ptr2);

    auto ret2 = munmap(ptr2, size);
    ASSERT_EQ(ret2, 0);

    ret = umfMemoryProviderFree(hProvider, ptr1, size);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    umfMemoryProviderDestroy(hProvider);
}

TEST_F(memspaceHostAllProviderTest, HostAllVsCopy) {
    umf_memspace_handle_t hMemspaceCopy = nullptr;
    auto ret = umfMemspaceNew(&hMemspaceCopy);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(hMemspaceCopy, nullptr);

    for (size_t i = 0; i < umfMemspaceMemtargetNum(hMemspace); ++i) {
        auto target = umfMemspaceMemtargetGet(hMemspace, i);
        ASSERT_NE(target, nullptr);

        ret = umfMemspaceMemtargetAdd(hMemspaceCopy, target);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    }

    ASSERT_EQ(umfMemspaceMemtargetNum(hMemspace),
              umfMemspaceMemtargetNum(hMemspaceCopy));

    umf_memory_provider_handle_t hProvider1, hProvider2;
    ret = umfMemoryProviderCreateFromMemspace(hMemspace, nullptr, &hProvider1);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(hProvider1, nullptr);

    ret = umfMemoryProviderCreateFromMemspace(hMemspaceCopy, nullptr,
                                              &hProvider2);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(hProvider2, nullptr);

    void *ptr1, *ptr2;
    ret = umfMemoryProviderAlloc(hProvider1, SIZE_4K, 0, &ptr1);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr1, nullptr);

    ret = umfMemoryProviderAlloc(hProvider2, SIZE_4K, 0, &ptr2);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    memset(ptr1, 0xFF, SIZE_4K);
    memset(ptr2, 0xFF, SIZE_4K);

    ASSERT_NODE_EQ(ptr1, ptr2);
    // HostAll memspace bind memory in the unique way (MPOL_DEFAULT),
    // but this works only for this specific memspaces, but not for it's copies.
    ASSERT_BIND_MASK_NE(ptr1, ptr2);
    ASSERT_BIND_MODE_NE(ptr1, ptr2);

    ASSERT_BIND_MODE_EQ(ptr1, MPOL_DEFAULT);
    ASSERT_BIND_MODE_EQ(ptr2, MPOL_BIND);

    ret = umfMemoryProviderFree(hProvider1, ptr1, SIZE_4K);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfMemoryProviderFree(hProvider2, ptr2, SIZE_4K);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    umfMemoryProviderDestroy(hProvider1);
    umfMemoryProviderDestroy(hProvider2);
    umfMemspaceDestroy(hMemspaceCopy);
}
