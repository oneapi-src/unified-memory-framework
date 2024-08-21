// Copyright (C) 2023-2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "base.hpp"
#include "memspace_fixtures.hpp"
#include "memspace_helpers.hpp"
#include "memspace_internal.h"
#include "numa_helpers.hpp"

#include <umf/memspace.h>
#include <umf/providers/provider_os_memory.h>

struct memspaceNumaTest : ::numaNodesTest {
    void SetUp() override {
        ::numaNodesTest::SetUp();

        if (numa_available() == -1) {
            GTEST_SKIP() << "NUMA not supported on this system; test skipped";
        }

        umf_result_t ret = umfMemspaceCreateFromNumaArray(
            nodeIds.data(), nodeIds.size(), &hMemspace);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        ASSERT_NE(hMemspace, nullptr);
    }

    void TearDown() override {
        ::numaNodesTest::TearDown();
        if (hMemspace) {
            umfMemspaceDestroy(hMemspace);
        }
    }

    umf_memspace_handle_t hMemspace = nullptr;
};

struct memspaceNumaProviderTest : ::memspaceNumaTest {
    void SetUp() override {
        ::memspaceNumaTest::SetUp();

        if (numa_available() == -1) {
            GTEST_SKIP() << "NUMA not supported on this system; test skipped";
        }

        umf_result_t ret =
            umfMemoryProviderCreateFromMemspace(hMemspace, nullptr, &hProvider);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        ASSERT_NE(hProvider, nullptr);
    }

    void TearDown() override {
        ::memspaceNumaTest::TearDown();

        if (hProvider != nullptr) {
            umfMemoryProviderDestroy(hProvider);
        }
    }

    umf_memory_provider_handle_t hProvider = nullptr;
};

TEST_F(numaNodesTest, createDestroy) {
    umf_memspace_handle_t hMemspace = nullptr;
    umf_result_t ret = umfMemspaceCreateFromNumaArray(
        nodeIds.data(), nodeIds.size(), &hMemspace);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(hMemspace, nullptr);
    EXPECT_EQ(umfMemspaceMemtargetNum(hMemspace), nodeIds.size());
    for (size_t i = 0; i < umfMemspaceMemtargetNum(hMemspace); ++i) {
        EXPECT_NE(umfMemspaceMemtargetGet(hMemspace, i), nullptr);
    }

    umfMemspaceDestroy(hMemspace);
}

TEST_F(numaNodesTest, createInvalidNullArray) {
    umf_memspace_handle_t hMemspace = nullptr;
    umf_result_t ret = umfMemspaceCreateFromNumaArray(NULL, 0, &hMemspace);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(hMemspace, nullptr);
}

TEST_F(numaNodesTest, createInvalidZeroSize) {
    umf_memspace_handle_t hMemspace = nullptr;
    umf_result_t ret =
        umfMemspaceCreateFromNumaArray(nodeIds.data(), 0, &hMemspace);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(hMemspace, nullptr);
}

TEST_F(numaNodesTest, createInvalidNullHandle) {
    umf_result_t ret =
        umfMemspaceCreateFromNumaArray(nodeIds.data(), nodeIds.size(), nullptr);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_F(memspaceNumaTest, providerFromNumaMemspace) {
    umf_memory_provider_handle_t hProvider = nullptr;
    umf_result_t ret =
        umfMemoryProviderCreateFromMemspace(hMemspace, nullptr, &hProvider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(hProvider, nullptr);

    umfMemoryProviderDestroy(hProvider);
}

TEST_F(memspaceNumaTest, memtargetsInvalid) {
    EXPECT_EQ(umfMemspaceMemtargetNum(nullptr), 0);
    EXPECT_EQ(umfMemspaceMemtargetGet(nullptr, 0), nullptr);

    ASSERT_EQ(umfMemspaceMemtargetNum(hMemspace), nodeIds.size());
    EXPECT_EQ(umfMemspaceMemtargetGet(hMemspace, nodeIds.size()), nullptr);
}

TEST_F(memspaceNumaTest, memspaceCopyTarget) {
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

    ASSERT_BIND_MASK_EQ(ptr1, ptr2);
    ASSERT_BIND_MODE_EQ(ptr1, ptr2);

    ret = umfMemoryProviderFree(hProvider1, ptr1, SIZE_4K);
    UT_ASSERTeq(ret, UMF_RESULT_SUCCESS);

    ret = umfMemoryProviderFree(hProvider2, ptr2, SIZE_4K);
    UT_ASSERTeq(ret, UMF_RESULT_SUCCESS);

    umfMemoryProviderDestroy(hProvider1);
    umfMemoryProviderDestroy(hProvider2);
    umfMemspaceDestroy(hMemspaceCopy);
}

TEST_F(memspaceNumaTest, memspaceDeleteTarget) {
    if (numa_max_node() < 2) {
        GTEST_SKIP() << "Not enough NUMA nodes to run test";
    }

    umf_memspace_handle_t hMemspaceCopy = nullptr;
    auto ret = umfMemspaceNew(&hMemspaceCopy);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(hMemspaceCopy, nullptr);

    auto target = umfMemspaceMemtargetGet(hMemspace, 0);
    ASSERT_NE(target, nullptr);

    ret = umfMemspaceMemtargetAdd(hMemspaceCopy, target);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    while (umfMemspaceMemtargetNum(hMemspace) > 1) {
        auto target = umfMemspaceMemtargetGet(hMemspace, 1);
        ASSERT_NE(target, nullptr);

        ret = umfMemspaceMemtargetRemove(hMemspace, target);
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

    ASSERT_BIND_MASK_EQ(ptr1, ptr2);
    ASSERT_BIND_MODE_EQ(ptr1, ptr2);

    ret = umfMemoryProviderFree(hProvider1, ptr1, SIZE_4K);
    UT_ASSERTeq(ret, UMF_RESULT_SUCCESS);

    ret = umfMemoryProviderFree(hProvider2, ptr2, SIZE_4K);
    UT_ASSERTeq(ret, UMF_RESULT_SUCCESS);

    umfMemoryProviderDestroy(hProvider1);
    umfMemoryProviderDestroy(hProvider2);
    umfMemspaceDestroy(hMemspaceCopy);
}

TEST_F(memspaceNumaProviderTest, allocFree) {
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
