// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "memory_provider_internal.h"
#include "memspace_helpers.hpp"
#include "provider_os_memory_internal.h"

os_memory_provider_t *providerGetPriv(umf_memory_provider_handle_t hProvider) {
    // hack to have access to fields in structure defined in memory_provider.c
    struct umf_memory_provider_t {
        umf_memory_provider_ops_t ops;
        void *provider_priv;
    } *provider = (struct umf_memory_provider_t *)hProvider;
    return (os_memory_provider_t *)provider->provider_priv;
}

using umf_test::test;
// mempolicy unit tests
TEST_F(test, mempolicyDefaultPreferred) {
    umf_memory_provider_handle_t hProvider = nullptr;
    umf_mempolicy_handle_t hPolicy = nullptr;

    umf_result_t ret = umfMempolicyCreate(UMF_MEMPOLICY_PREFERRED, &hPolicy);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfMemoryProviderCreateFromMemspace(umfMemspaceHostAllGet(), hPolicy,
                                              &hProvider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(hProvider, nullptr);
    ret = umfMempolicyDestroy(hPolicy);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    os_memory_provider_t *ProviderInternal =
        (os_memory_provider_t *)providerGetPriv(hProvider);
    ASSERT_NE(ProviderInternal, nullptr);
    EXPECT_EQ(ProviderInternal->numa_policy, HWLOC_MEMBIND_BIND);
    EXPECT_EQ(ProviderInternal->numa_flags, HWLOC_MEMBIND_BYNODESET);
    EXPECT_EQ(ProviderInternal->mode, UMF_NUMA_MODE_PREFERRED);
    umfMemoryProviderDestroy(hProvider);
}

TEST_F(test, mempolicyDefaultBind) {
    umf_memory_provider_handle_t hProvider = nullptr;
    umf_mempolicy_handle_t hPolicy = nullptr;

    umf_result_t ret = umfMempolicyCreate(UMF_MEMPOLICY_BIND, &hPolicy);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfMemoryProviderCreateFromMemspace(umfMemspaceHostAllGet(), hPolicy,
                                              &hProvider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(hProvider, nullptr);
    ret = umfMempolicyDestroy(hPolicy);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    os_memory_provider_t *ProviderInternal =
        (os_memory_provider_t *)providerGetPriv(hProvider);
    ASSERT_NE(ProviderInternal, nullptr);
    EXPECT_EQ(ProviderInternal->numa_policy, HWLOC_MEMBIND_BIND);
    EXPECT_EQ(ProviderInternal->numa_flags,
              HWLOC_MEMBIND_BYNODESET | HWLOC_MEMBIND_STRICT);
    EXPECT_EQ(ProviderInternal->mode, UMF_NUMA_MODE_BIND);
    umfMemoryProviderDestroy(hProvider);
}

TEST_F(test, mempolicyDefaultInterleave) {
    umf_memory_provider_handle_t hProvider = nullptr;
    umf_mempolicy_handle_t hPolicy = nullptr;

    umf_result_t ret = umfMempolicyCreate(UMF_MEMPOLICY_INTERLEAVE, &hPolicy);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfMemoryProviderCreateFromMemspace(umfMemspaceHostAllGet(), hPolicy,
                                              &hProvider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(hProvider, nullptr);
    ret = umfMempolicyDestroy(hPolicy);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    os_memory_provider_t *ProviderInternal =
        (os_memory_provider_t *)providerGetPriv(hProvider);
    ASSERT_NE(ProviderInternal, nullptr);
    EXPECT_EQ(ProviderInternal->numa_policy, HWLOC_MEMBIND_INTERLEAVE);
    EXPECT_EQ(ProviderInternal->numa_flags, HWLOC_MEMBIND_BYNODESET);
    EXPECT_EQ(ProviderInternal->part_size, 0);
    EXPECT_EQ(ProviderInternal->mode, UMF_NUMA_MODE_INTERLEAVE);
    umfMemoryProviderDestroy(hProvider);
}

TEST_F(test, mempolicyInterleavePartSize) {
    const size_t part_size = 100;
    umf_memory_provider_handle_t hProvider = nullptr;
    umf_mempolicy_handle_t hPolicy = nullptr;

    umf_result_t ret = umfMempolicyCreate(UMF_MEMPOLICY_INTERLEAVE, &hPolicy);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ret = umfMempolicySetInterleavePartSize(hPolicy, part_size);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfMemoryProviderCreateFromMemspace(umfMemspaceHostAllGet(), hPolicy,
                                              &hProvider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(hProvider, nullptr);
    ret = umfMempolicyDestroy(hPolicy);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    os_memory_provider_t *ProviderInternal =
        (os_memory_provider_t *)providerGetPriv(hProvider);
    ASSERT_NE(ProviderInternal, nullptr);
    EXPECT_EQ(ProviderInternal->numa_policy, HWLOC_MEMBIND_BIND);
    EXPECT_EQ(ProviderInternal->numa_flags,
              HWLOC_MEMBIND_BYNODESET | HWLOC_MEMBIND_STRICT);
    EXPECT_EQ(ProviderInternal->part_size, part_size);
    EXPECT_EQ(ProviderInternal->mode, UMF_NUMA_MODE_INTERLEAVE);
    umfMemoryProviderDestroy(hProvider);
}

TEST_F(test, mempolicyDefaultSplit) {
    umf_memory_provider_handle_t hProvider = nullptr;
    umf_mempolicy_handle_t hPolicy = nullptr;

    umf_result_t ret = umfMempolicyCreate(UMF_MEMPOLICY_SPLIT, &hPolicy);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfMemoryProviderCreateFromMemspace(umfMemspaceHostAllGet(), hPolicy,
                                              &hProvider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(hProvider, nullptr);
    ret = umfMempolicyDestroy(hPolicy);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    os_memory_provider_t *ProviderInternal =
        (os_memory_provider_t *)providerGetPriv(hProvider);
    ASSERT_NE(ProviderInternal, nullptr);
    EXPECT_EQ(ProviderInternal->numa_policy, HWLOC_MEMBIND_BIND);
    EXPECT_EQ(ProviderInternal->numa_flags,
              HWLOC_MEMBIND_BYNODESET | HWLOC_MEMBIND_STRICT);
    EXPECT_EQ(ProviderInternal->partitions_len, ProviderInternal->nodeset_len);
    EXPECT_EQ(ProviderInternal->mode, UMF_NUMA_MODE_SPLIT);
    umfMemoryProviderDestroy(hProvider);
}

TEST_F(test, mempolicyCustomSplit) {
    umf_memory_provider_handle_t hProvider = nullptr;
    umf_mempolicy_handle_t hPolicy = nullptr;

    umf_result_t ret = umfMempolicyCreate(UMF_MEMPOLICY_SPLIT, &hPolicy);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    umf_mempolicy_split_partition_t part[] = {{1, 0}, {1, 0}};

    ret = umfMempolicySetCustomSplitPartitions(hPolicy, part, 2);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfMemoryProviderCreateFromMemspace(umfMemspaceHostAllGet(), hPolicy,
                                              &hProvider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(hProvider, nullptr);
    ret = umfMempolicyDestroy(hPolicy);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    os_memory_provider_t *ProviderInternal =
        (os_memory_provider_t *)providerGetPriv(hProvider);
    ASSERT_NE(ProviderInternal, nullptr);
    EXPECT_EQ(ProviderInternal->numa_policy, HWLOC_MEMBIND_BIND);
    EXPECT_EQ(ProviderInternal->numa_flags,
              HWLOC_MEMBIND_BYNODESET | HWLOC_MEMBIND_STRICT);
    EXPECT_EQ(ProviderInternal->partitions_len, 2);
    EXPECT_EQ(ProviderInternal->mode, UMF_NUMA_MODE_SPLIT);
    EXPECT_EQ(ProviderInternal->partitions_weight_sum, 2);
    EXPECT_EQ(ProviderInternal->partitions[0].target,
              ProviderInternal->partitions[1].target);
    umfMemoryProviderDestroy(hProvider);
}

TEST_F(test, mempolicySplitNegative) {
    umf_mempolicy_handle_t hPolicy = nullptr;

    umf_result_t ret = umfMempolicyCreate(UMF_MEMPOLICY_BIND, &hPolicy);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    umf_mempolicy_split_partition_t part[] = {{1, 0}, {1, 0}};

    ret = umfMempolicySetCustomSplitPartitions(hPolicy, part, 2);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = umfMempolicySetCustomSplitPartitions(NULL, part, 2);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ret = umfMempolicyDestroy(hPolicy);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
}
