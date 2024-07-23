// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "memspace_helpers.hpp"

#include <umf/base.h>
#include <umf/memspace.h>
#include <umf/memtarget.h>

using umf_test::test;

TEST_F(test, memTargetNuma) {
    auto memspace = umfMemspaceHostAllGet();
    ASSERT_NE(memspace, nullptr);

    for (size_t i = 0; i < umfMemspaceMemtargetNum(memspace); i++) {
        auto hTarget = umfMemspaceMemtargetGet(memspace, i);
        ASSERT_NE(hTarget, nullptr);
        umf_memtarget_type_t type;
        auto ret = umfMemtargetGetType(hTarget, &type);
        EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
        EXPECT_EQ(type, UMF_MEMTARGET_TYPE_NUMA);
    }
}

TEST_F(test, memTargetInvalid) {
    auto memspace = umfMemspaceHostAllGet();
    ASSERT_NE(memspace, nullptr);
    umf_memtarget_type_t type;
    auto ret = umfMemtargetGetType(NULL, &type);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ret = umfMemtargetGetType(NULL, NULL);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    auto hTarget = umfMemspaceMemtargetGet(memspace, 0);
    ASSERT_NE(hTarget, nullptr);
    ret = umfMemtargetGetType(hTarget, NULL);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}
