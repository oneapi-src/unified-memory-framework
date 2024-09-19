// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "memspace_fixtures.hpp"
#include "memspace_helpers.hpp"

#include <umf/base.h>
#include <umf/memspace.h>
#include <umf/memtarget.h>

using umf_test::test;

TEST_F(test, memTargetNuma) {
    auto memspace = umfMemspaceHostAllGet();
    ASSERT_NE(memspace, nullptr);
    umf_memtarget_type_t type;
    for (size_t i = 0; i < umfMemspaceMemtargetNum(memspace); i++) {
        auto hTarget = umfMemspaceMemtargetGet(memspace, i);
        ASSERT_NE(hTarget, nullptr);
        auto ret = umfMemtargetGetType(hTarget, &type);
        EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
        EXPECT_EQ(type, UMF_MEMTARGET_TYPE_NUMA);
    }
}

TEST_F(numaNodesCapacityTest, getCapacity) {
    auto memspace = umfMemspaceHostAllGet();
    ASSERT_NE(memspace, nullptr);

    for (size_t i = 0; i < umfMemspaceMemtargetNum(memspace); i++) {
        auto hTarget = umfMemspaceMemtargetGet(memspace, i);
        ASSERT_NE(hTarget, nullptr);
        size_t capacity;
        auto ret = umfMemtargetGetCapacity(hTarget, &capacity);
        EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
        auto it = std::find(capacities.begin(), capacities.end(), capacity);
        EXPECT_NE(it, capacities.end());
        if (it != capacities.end()) {
            capacities.erase(it);
        }
    }
    ASSERT_EQ(capacities.size(), 0);
}

TEST_F(numaNodesTest, getId) {
    auto memspace = umfMemspaceHostAllGet();
    ASSERT_NE(memspace, nullptr);

    for (size_t i = 0; i < umfMemspaceMemtargetNum(memspace); i++) {
        auto hTarget = umfMemspaceMemtargetGet(memspace, i);
        ASSERT_NE(hTarget, nullptr);
        unsigned id;
        auto ret = umfMemtargetGetId(hTarget, &id);
        EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
        auto it = std::find(nodeIds.begin(), nodeIds.end(), id);
        EXPECT_NE(it, nodeIds.end());
        if (it != nodeIds.end()) {
            nodeIds.erase(it);
        }
    }
    ASSERT_EQ(nodeIds.size(), 0);
}

TEST_F(numaNodesTest, getCapacityInvalid) {
    auto memspace = umfMemspaceHostAllGet();
    ASSERT_NE(memspace, nullptr);
    size_t capacity;
    auto ret = umfMemtargetGetCapacity(NULL, &capacity);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ret = umfMemtargetGetCapacity(NULL, NULL);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    auto hTarget = umfMemspaceMemtargetGet(memspace, 0);
    ASSERT_NE(hTarget, nullptr);
    ret = umfMemtargetGetCapacity(hTarget, NULL);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
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

TEST_F(numaNodesTest, getIdInvalid) {
    auto memspace = umfMemspaceHostAllGet();
    ASSERT_NE(memspace, nullptr);
    unsigned id;
    auto ret = umfMemtargetGetId(NULL, &id);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ret = umfMemtargetGetId(NULL, NULL);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    auto hTarget = umfMemspaceMemtargetGet(memspace, 0);
    ASSERT_NE(hTarget, nullptr);
    ret = umfMemtargetGetId(hTarget, NULL);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}
