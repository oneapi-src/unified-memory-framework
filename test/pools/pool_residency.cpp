// Copyright (C) 2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "../common/level_zero_mocks.h"
#include "pool.hpp"
#include "umf/pools/pool_disjoint.h"
#include "umf/providers/provider_level_zero.h"

#include "gtest/gtest.h"

using namespace testing;

class PoolResidencyTestFixture : public Test {
  protected:
    umf_memory_pool_handle_t pool = nullptr;
    const ze_device_handle_t OUR_DEVICE;
    StrictMock<LevelZeroMock> l0mock;

    PoolResidencyTestFixture()
        : OUR_DEVICE(TestCreatePointer<ze_device_handle_t>(777)) {
        *MockedLevelZeroTestEnvironment::l0interface = &l0mock;
    }

    void initializeMemoryPool(umf_memory_provider_handle_t provider) {

        auto *params = static_cast<umf_disjoint_pool_params_handle_t>(
            umf_test::defaultDisjointPoolConfig());

        EXPECT_EQ(umfPoolCreate(umfDisjointPoolOps(), provider, params,
                                UMF_POOL_CREATE_FLAG_OWN_PROVIDER, &pool),
                  UMF_RESULT_SUCCESS);

        umf_test::defaultDisjointPoolConfigDestroy(params);
    }

    void SetUp() override {}
    void TearDown() override {
        if (pool != nullptr) {
            EXPECT_CALL(l0mock, zeMemFree(CONTEXT, _))
                .WillRepeatedly(Return(ZE_RESULT_SUCCESS));
            umfPoolDestroy(pool);
        }
        Mock::VerifyAndClearExpectations(&l0mock);
    }
};

TEST_F(PoolResidencyTestFixture,
       initialResidentDevicesShouldBeUsedDuringAllocation) {
    initializeMemoryPool(l0mock.initializeMemoryProviderWithResidentDevices(
        OUR_DEVICE, {DEVICE_0, DEVICE_1}));

    EXPECT_CALL(l0mock, zeMemAllocDevice(CONTEXT, _, _, _, OUR_DEVICE, _))
        .WillOnce(
            DoAll(SetArgPointee<5>(POINTER_0), Return(ZE_RESULT_SUCCESS)));
    EXPECT_CALL(l0mock, zeContextMakeMemoryResident(CONTEXT, DEVICE_0, _, _))
        .WillOnce(Return(ZE_RESULT_SUCCESS));
    EXPECT_CALL(l0mock, zeContextMakeMemoryResident(CONTEXT, DEVICE_1, _, _))
        .WillOnce(Return(ZE_RESULT_SUCCESS));

    void *ptr = umfPoolMalloc(pool, 123);
    EXPECT_EQ(ptr, POINTER_0);

    umfPoolFree(pool, ptr);
}

TEST_F(PoolResidencyTestFixture,
       addedResidentDevicesShouldBeUsedDuringAllocation) {
    initializeMemoryPool(l0mock.initializeMemoryProviderWithResidentDevices(
        OUR_DEVICE, {DEVICE_0}));

    umf_memory_provider_handle_t provider = nullptr;
    EXPECT_EQ(umfPoolGetMemoryProvider(pool, &provider), UMF_RESULT_SUCCESS);
    umfLevelZeroMemoryProviderResidentDeviceChange(provider, DEVICE_4, true);

    EXPECT_CALL(l0mock, zeMemAllocDevice(CONTEXT, _, _, _, OUR_DEVICE, _))
        .WillOnce(
            DoAll(SetArgPointee<5>(POINTER_0), Return(ZE_RESULT_SUCCESS)));
    EXPECT_CALL(l0mock, zeContextMakeMemoryResident(CONTEXT, DEVICE_0, _, _))
        .WillOnce(Return(ZE_RESULT_SUCCESS));
    EXPECT_CALL(l0mock, zeContextMakeMemoryResident(CONTEXT, DEVICE_4, _, _))
        .WillOnce(Return(ZE_RESULT_SUCCESS));

    void *ptr = umfPoolMalloc(pool, 123);
    EXPECT_EQ(ptr, POINTER_0);

    umfPoolFree(pool, ptr);
}

TEST_F(PoolResidencyTestFixture,
       existingAllocationsShouldBeMadeResidentOnAddedDevice) {
    initializeMemoryPool(
        l0mock.initializeMemoryProviderWithResidentDevices(OUR_DEVICE, {}));

    EXPECT_CALL(l0mock, zeMemAllocDevice(CONTEXT, _, _, _, OUR_DEVICE, _))
        .WillOnce(
            DoAll(SetArgPointee<5>(POINTER_0), Return(ZE_RESULT_SUCCESS)));

    void *ptr = umfPoolMalloc(pool, 123);
    EXPECT_EQ(ptr, POINTER_0);

    EXPECT_CALL(l0mock, zeContextMakeMemoryResident(CONTEXT, DEVICE_4, _, _))
        .WillOnce(Return(ZE_RESULT_SUCCESS));

    umf_memory_provider_handle_t provider = nullptr;
    EXPECT_EQ(umfPoolGetMemoryProvider(pool, &provider), UMF_RESULT_SUCCESS);
    umfLevelZeroMemoryProviderResidentDeviceChange(provider, DEVICE_4, true);

    umfPoolFree(pool, ptr);
}

TEST_F(PoolResidencyTestFixture,
       allocationShouldNotBeMadeResidentOnRemovedDevice) {
    initializeMemoryPool(l0mock.initializeMemoryProviderWithResidentDevices(
        OUR_DEVICE, {DEVICE_2}));

    umf_memory_provider_handle_t provider = nullptr;
    EXPECT_EQ(umfPoolGetMemoryProvider(pool, &provider), UMF_RESULT_SUCCESS);
    umfLevelZeroMemoryProviderResidentDeviceChange(provider, DEVICE_2, false);

    EXPECT_CALL(l0mock, zeMemAllocDevice(CONTEXT, _, _, _, OUR_DEVICE, _))
        .WillOnce(
            DoAll(SetArgPointee<5>(POINTER_0), Return(ZE_RESULT_SUCCESS)));
    EXPECT_CALL(l0mock, zeContextMakeMemoryResident(CONTEXT, DEVICE_2, _, _))
        .Times(0); // not called

    void *ptr = umfPoolMalloc(pool, 123);
    EXPECT_EQ(ptr, POINTER_0);

    umfPoolFree(pool, ptr);
}

TEST_F(PoolResidencyTestFixture,
       allocationThatFailedToBeMadeResidedShouldBeFreed) {
    initializeMemoryPool(l0mock.initializeMemoryProviderWithResidentDevices(
        OUR_DEVICE, {DEVICE_2}));

    EXPECT_CALL(l0mock, zeMemAllocDevice(CONTEXT, _, _, _, OUR_DEVICE, _))
        .WillOnce(
            DoAll(SetArgPointee<5>(POINTER_0), Return(ZE_RESULT_SUCCESS)));
    EXPECT_CALL(l0mock, zeContextMakeMemoryResident(CONTEXT, DEVICE_2, _, _))
        .WillOnce(Return(ZE_RESULT_ERROR_DEVICE_LOST));
    EXPECT_CALL(l0mock, zeMemFree(CONTEXT, _))
        .WillOnce(Return(ZE_RESULT_ERROR_DEVICE_IN_LOW_POWER_STATE));

    void *ptr = umfPoolMalloc(pool, 16 * 1024 * 1024);
    EXPECT_EQ(ptr, nullptr);

    umfPoolFree(pool, ptr);
}

int main(int argc, char **argv) {
    InitGoogleTest(&argc, argv);
    AddGlobalTestEnvironment(new MockedLevelZeroTestEnvironment);
    return RUN_ALL_TESTS();
}
