// Copyright (C) 2024-2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "memspace_helpers.hpp"

using umf_test::test;

TEST_F(test, memspaceNewInvalid) {
    auto ret = umfMemspaceNew(NULL);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

class emptyMemspace : public testing::Test {
  public:
    umf_memspace_handle_t memspace;

    void SetUp() override {
        auto ret = umfMemspaceNew(&memspace);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        ASSERT_NE(memspace, nullptr);
    }
    void TearDown() override { umfMemspaceDestroy(memspace); }
};

TEST_F(emptyMemspace, basic) {
    size_t len = umfMemspaceMemtargetNum(memspace);
    ASSERT_EQ(len, 0);
}

TEST_F(emptyMemspace, create_pool) {
    umf_memory_pool_handle_t pool = nullptr;
    auto ret = umfPoolCreateFromMemspace(memspace, NULL, &pool);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(pool, nullptr);
}

TEST_F(emptyMemspace, invalid_create_from_memspace) {
    umf_memory_provider_handle_t provider = nullptr;
    umf_mempolicy_handle_t policy = nullptr;

    // invalid memspace
    umf_result_t ret =
        umfMemoryProviderCreateFromMemspace(NULL, policy, &provider);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(provider, nullptr);

    // invalid provider
    ret = umfMemoryProviderCreateFromMemspace(memspace, policy, nullptr);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // Valid params, but memspace is empty
    ret = umfMemoryProviderCreateFromMemspace(memspace, policy, &provider);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(provider, nullptr);
}

TEST_F(emptyMemspace, invalid_clone) {
    umf_const_memspace_handle_t memspace = nullptr;
    umf_memspace_handle_t out_memspace = nullptr;

    umf_result_t ret = umfMemspaceClone(memspace, nullptr);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = umfMemspaceClone(nullptr, &out_memspace);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}
