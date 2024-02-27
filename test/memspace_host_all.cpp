// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "base.hpp"
#include "test_helpers.h"

#include <umf/memspace.h>

using umf_test::test;

#define SIZE_4K (4096)

struct predefinedMemspaceTest : test {

    void SetUp() override {
        ::test::SetUp();

        hMemspace = umfMemspaceHostAllGet();
        UT_ASSERTne(hMemspace, nullptr);
    }

    umf_memspace_handle_t hMemspace;
};

struct predefinedMemspaceProviderTest : predefinedMemspaceTest {

    void SetUp() override {
        ::predefinedMemspaceTest::SetUp();

        enum umf_result_t ret =
            umfMemoryProviderCreateFromMemspace(hMemspace, nullptr, &provider);
        UT_ASSERTeq(ret, UMF_RESULT_SUCCESS);
        UT_ASSERTne(provider, nullptr);
    }

    void TearDown() override {
        ::predefinedMemspaceTest::TearDown();

        umfMemoryProviderDestroy(provider);
    }

    umf_memory_provider_handle_t provider = nullptr;
};

TEST_F(test, memspaceGet) {
    umf_memspace_handle_t hMemspace = umfMemspaceHostAllGet();
    UT_ASSERTne(hMemspace, nullptr);
}

TEST_F(predefinedMemspaceProviderTest, allocFree) {
    void *ptr = nullptr;
    size_t size = SIZE_4K;
    size_t alignment = 0;

    enum umf_result_t ret =
        umfMemoryProviderAlloc(provider, size, alignment, &ptr);
    UT_ASSERTeq(ret, UMF_RESULT_SUCCESS);
    UT_ASSERTne(ptr, nullptr);

    memset(ptr, 0xFF, size);

    ret = umfMemoryProviderFree(provider, ptr, size);
    UT_ASSERTeq(ret, UMF_RESULT_SUCCESS);
}
