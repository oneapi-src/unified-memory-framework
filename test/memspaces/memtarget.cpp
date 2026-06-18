// Copyright (C) 2024-2026 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "memspace_fixtures.hpp"
#include "memspace_helpers.hpp"

#include <umf/base.h>
#include <umf/experimental/memspace.h>
#include <umf/experimental/memtarget.h>

#include "memtarget_internal.h"
#include "memtarget_ops.h"

using umf_test::test;

namespace {

struct fake_target_t {
    unsigned id;
};

int finalizeCount;

umf_result_t fakeInitialize(void *params, void **memoryTarget) {
    if (!params || !memoryTarget) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    auto target = static_cast<fake_target_t *>(malloc(sizeof(fake_target_t)));
    if (!target) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    target->id = *static_cast<unsigned *>(params);
    *memoryTarget = target;
    return UMF_RESULT_SUCCESS;
}

void fakeFinalize(void *memoryTarget) {
    finalizeCount++;
    free(memoryTarget);
}

umf_result_t fakeClone(void *memoryTarget, void **outMemoryTarget) {
    if (!memoryTarget || !outMemoryTarget) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    auto source = static_cast<fake_target_t *>(memoryTarget);
    auto target = static_cast<fake_target_t *>(malloc(sizeof(fake_target_t)));
    if (!target) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    target->id = source->id;
    *outMemoryTarget = target;
    return UMF_RESULT_SUCCESS;
}

umf_result_t fakePoolCreateFromMemspace(umf_const_memspace_handle_t memspace,
                                        void **memoryTargets, size_t numTargets,
                                        umf_const_mempolicy_handle_t policy,
                                        umf_memory_pool_handle_t *pool) {
    (void)memspace;
    (void)memoryTargets;
    (void)numTargets;
    (void)policy;
    (void)pool;
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

umf_result_t
fakeMemoryProviderCreateFromMemspace(umf_const_memspace_handle_t memspace,
                                     void **memoryTargets, size_t numTargets,
                                     umf_const_mempolicy_handle_t policy,
                                     umf_memory_provider_handle_t *provider) {
    (void)memspace;
    (void)memoryTargets;
    (void)numTargets;
    (void)policy;
    (void)provider;
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

umf_result_t fakeGetCapacity(void *memoryTarget, size_t *capacity) {
    (void)memoryTarget;
    *capacity = 4096;
    return UMF_RESULT_SUCCESS;
}

umf_result_t fakeGetBandwidth(void *srcMemoryTarget, void *dstMemoryTarget,
                              size_t *bandwidth) {
    (void)srcMemoryTarget;
    (void)dstMemoryTarget;
    *bandwidth = 1;
    return UMF_RESULT_SUCCESS;
}

umf_result_t fakeGetLatency(void *srcMemoryTarget, void *dstMemoryTarget,
                            size_t *latency) {
    (void)srcMemoryTarget;
    (void)dstMemoryTarget;
    *latency = 1;
    return UMF_RESULT_SUCCESS;
}

umf_result_t fakeGetType(void *memoryTarget, umf_memtarget_type_t *type) {
    (void)memoryTarget;
    *type = UMF_MEMTARGET_TYPE_NUMA;
    return UMF_RESULT_SUCCESS;
}

umf_result_t fakeGetId(void *memoryTarget, unsigned *id) {
    *id = static_cast<fake_target_t *>(memoryTarget)->id;
    return UMF_RESULT_SUCCESS;
}

umf_result_t fakeCompare(void *memTarget, void *otherMemTarget, int *result) {
    auto left = static_cast<fake_target_t *>(memTarget);
    auto right = static_cast<fake_target_t *>(otherMemTarget);

    if (finalizeCount > 0 && left->id == 2 && right->id == 2) {
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    *result = left->id == right->id ? 0 : 1;
    return UMF_RESULT_SUCCESS;
}

const umf_memtarget_ops_t FAKE_OPS = {
    .version = UMF_MEMTARGET_OPS_VERSION_CURRENT,
    .initialize = fakeInitialize,
    .finalize = fakeFinalize,
    .clone = fakeClone,
    .pool_create_from_memspace = fakePoolCreateFromMemspace,
    .memory_provider_create_from_memspace =
        fakeMemoryProviderCreateFromMemspace,
    .get_capacity = fakeGetCapacity,
    .get_bandwidth = fakeGetBandwidth,
    .get_latency = fakeGetLatency,
    .get_type = fakeGetType,
    .get_id = fakeGetId,
    .compare = fakeCompare,
};

} // namespace

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

TEST_F(test, memTargetInvalidAdd) {
    umf_const_memspace_handle_t const_memspace = umfMemspaceHostAllGet();
    umf_memspace_handle_t memspace = nullptr;
    umf_result_t ret = umfMemspaceClone(const_memspace, &memspace);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(memspace, nullptr);
    umf_const_memtarget_handle_t memtarget =
        umfMemspaceMemtargetGet(memspace, 0);

    ret = umfMemspaceMemtargetAdd(memspace, nullptr);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = umfMemspaceMemtargetAdd(nullptr, memtarget);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // Try to add the same memtarget again
    ret = umfMemspaceMemtargetAdd(memspace, memtarget);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = umfMemspaceDestroy(memspace);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
}

TEST_F(test, memTargetInvalidRemove) {
    umf_const_memspace_handle_t const_memspace = umfMemspaceHostAllGet();
    umf_memspace_handle_t memspace = nullptr;
    umf_result_t ret = umfMemspaceClone(const_memspace, &memspace);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(memspace, nullptr);
    umf_const_memtarget_handle_t memtarget =
        umfMemspaceMemtargetGet(memspace, 0);

    ret = umfMemspaceMemtargetRemove(memspace, nullptr);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = umfMemspaceMemtargetRemove(nullptr, memtarget);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = umfMemspaceDestroy(memspace);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
}

TEST_F(test, memTargetRemoveAll) {
    umf_const_memspace_handle_t const_memspace = umfMemspaceHostAllGet();
    umf_memspace_handle_t memspace = nullptr;
    umf_result_t ret = umfMemspaceClone(const_memspace, &memspace);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(memspace, nullptr);
    umf_const_memtarget_handle_t memtarget = nullptr;

    // Remove all memtargets
    size_t len = umfMemspaceMemtargetNum(memspace);
    ASSERT_GT(len, 0);
    size_t i = len - 1;
    do {
        memtarget = umfMemspaceMemtargetGet(memspace, i);
        EXPECT_NE(memtarget, nullptr);
        ret = umfMemspaceMemtargetRemove(memspace, memtarget);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    } while (i-- > 0);

    // Try to remove the last one for the second time
    ret = umfMemspaceMemtargetRemove(memspace, memtarget);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = umfMemspaceDestroy(memspace);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
}

TEST_F(test, memTargetFilterRollback) {
    finalizeCount = 0;

    umf_memspace_handle_t memspace = nullptr;
    umf_result_t ret = umfMemspaceNew(&memspace);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(memspace, nullptr);

    umf_memtarget_handle_t target1 = nullptr;
    umf_memtarget_handle_t target2 = nullptr;
    umf_memtarget_handle_t target3 = nullptr;
    unsigned id1 = 1;
    unsigned id2 = 2;
    unsigned id3 = 3;

    ret = umfMemtargetCreate(&FAKE_OPS, &id1, &target1);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ret = umfMemtargetCreate(&FAKE_OPS, &id2, &target2);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ret = umfMemtargetCreate(&FAKE_OPS, &id3, &target3);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfMemspaceMemtargetAdd(memspace, target1);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ret = umfMemspaceMemtargetAdd(memspace, target2);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ret = umfMemspaceMemtargetAdd(memspace, target3);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfMemspaceUserFilter(
        memspace,
        [](umf_const_memspace_handle_t, umf_const_memtarget_handle_t,
           void *) -> int {
            // filter everything
            return 0;
        },
        nullptr);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_UNKNOWN);
    ASSERT_EQ(umfMemspaceMemtargetNum(memspace), 3u);

    std::vector<unsigned> ids;
    for (size_t targetIdx = 0; targetIdx < umfMemspaceMemtargetNum(memspace);
         targetIdx++) {
        auto target = umfMemspaceMemtargetGet(memspace, targetIdx);
        ASSERT_NE(target, nullptr);

        unsigned id = 0;
        ret = umfMemtargetGetId(target, &id);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        ids.push_back(id);
    }

    std::sort(ids.begin(), ids.end());
    EXPECT_EQ(ids, (std::vector<unsigned>{1, 2, 3}));

    ret = umfMemspaceDestroy(memspace);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    umfMemtargetDestroy(target1);
    umfMemtargetDestroy(target2);
    umfMemtargetDestroy(target3);
}

TEST_F(test, memTargetFilterRemoveOnlyId2) {
    finalizeCount = 0;

    umf_memspace_handle_t memspace = nullptr;
    umf_result_t ret = umfMemspaceNew(&memspace);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(memspace, nullptr);

    umf_memtarget_handle_t target1 = nullptr;
    umf_memtarget_handle_t target2 = nullptr;
    umf_memtarget_handle_t target3 = nullptr;
    unsigned id1 = 1;
    unsigned id2 = 2;
    unsigned id3 = 3;

    ret = umfMemtargetCreate(&FAKE_OPS, &id1, &target1);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ret = umfMemtargetCreate(&FAKE_OPS, &id2, &target2);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ret = umfMemtargetCreate(&FAKE_OPS, &id3, &target3);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfMemspaceMemtargetAdd(memspace, target1);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ret = umfMemspaceMemtargetAdd(memspace, target2);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ret = umfMemspaceMemtargetAdd(memspace, target3);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfMemspaceUserFilter(
        memspace,
        [](umf_const_memspace_handle_t, umf_const_memtarget_handle_t target,
           void *args) -> int {
            // filter out target with id passed in args, keep the rest
            unsigned targetId = 0;
            (void)umfMemtargetGetId(target, &targetId);
            return targetId == *static_cast<unsigned *>(args) ? 0 : 1;
        },
        &id2);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(umfMemspaceMemtargetNum(memspace), 2u);

    std::vector<unsigned> ids;
    for (size_t targetIdx = 0; targetIdx < umfMemspaceMemtargetNum(memspace);
         targetIdx++) {
        auto target = umfMemspaceMemtargetGet(memspace, targetIdx);
        ASSERT_NE(target, nullptr);

        unsigned id = 0;
        ret = umfMemtargetGetId(target, &id);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
        ids.push_back(id);
    }

    std::sort(ids.begin(), ids.end());
    EXPECT_EQ(ids, (std::vector<unsigned>{1, 3}));

    ret = umfMemspaceDestroy(memspace);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    umfMemtargetDestroy(target1);
    umfMemtargetDestroy(target2);
    umfMemtargetDestroy(target3);
}
