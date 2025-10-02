// Copyright (C) 2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "../common/level_zero_mocks.h"
#include "utils_level_zero.h"
#include "utils_log.h"

#include "gtest/gtest.h"

using namespace testing;

class LevelZeroResidencyTestFixture : public Test {
  protected:
    StrictMock<LevelZeroMock> l0mock;
    umf_memory_provider_handle_t provider = nullptr;
    const ze_device_handle_t OUR_DEVICE;

    LevelZeroResidencyTestFixture()
        : OUR_DEVICE(TestCreatePointer<ze_device_handle_t>(777)) {
        *MockedLevelZeroTestEnvironment::l0interface = &l0mock;
    }

    void SetUp() override {}
    void TearDown() override {
        Mock::VerifyAndClearExpectations(&l0mock);
        umfMemoryProviderDestroy(provider);
    }
};

TEST_F(LevelZeroResidencyTestFixture, addNonexistingDeviceShouldSucceed) {
    provider = l0mock.initializeMemoryProviderWithResidentDevices(
        OUR_DEVICE, {DEVICE_1, DEVICE_5, DEVICE_3});
    ASSERT_EQ(umfLevelZeroMemoryProviderResidentDeviceChange(provider, DEVICE_2,
                                                             true),
              UMF_RESULT_SUCCESS);
}

TEST_F(LevelZeroResidencyTestFixture, addExistingDeviceShouldFail) {
    provider = l0mock.initializeMemoryProviderWithResidentDevices(
        OUR_DEVICE, {DEVICE_1, DEVICE_5, DEVICE_3});
    ASSERT_EQ(umfLevelZeroMemoryProviderResidentDeviceChange(provider, DEVICE_5,
                                                             true),
              UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_F(LevelZeroResidencyTestFixture, removeNonexistingDeviceShouldFail) {
    provider = l0mock.initializeMemoryProviderWithResidentDevices(
        OUR_DEVICE, {DEVICE_1, DEVICE_5, DEVICE_3});
    ASSERT_EQ(umfLevelZeroMemoryProviderResidentDeviceChange(provider, DEVICE_0,
                                                             false),
              UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_F(LevelZeroResidencyTestFixture, removeExistingDeviceShouldSucceed) {
    provider = l0mock.initializeMemoryProviderWithResidentDevices(
        OUR_DEVICE, {DEVICE_1, DEVICE_5, DEVICE_3});
    ASSERT_EQ(umfLevelZeroMemoryProviderResidentDeviceChange(provider, DEVICE_1,
                                                             false),
              UMF_RESULT_SUCCESS);
}

TEST_F(LevelZeroResidencyTestFixture, addDeviceTwiceShouldFail) {
    provider = l0mock.initializeMemoryProviderWithResidentDevices(
        OUR_DEVICE, {DEVICE_1, DEVICE_5, DEVICE_3});
    ASSERT_EQ(umfLevelZeroMemoryProviderResidentDeviceChange(provider, DEVICE_2,
                                                             true),
              UMF_RESULT_SUCCESS);
    ASSERT_EQ(umfLevelZeroMemoryProviderResidentDeviceChange(provider, DEVICE_2,
                                                             true),
              UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_F(LevelZeroResidencyTestFixture, removeDeviceTwiceShouldFail) {
    provider = l0mock.initializeMemoryProviderWithResidentDevices(
        OUR_DEVICE, {DEVICE_1, DEVICE_5, DEVICE_3});
    ASSERT_EQ(umfLevelZeroMemoryProviderResidentDeviceChange(provider, DEVICE_3,
                                                             false),
              UMF_RESULT_SUCCESS);
    ASSERT_EQ(umfLevelZeroMemoryProviderResidentDeviceChange(provider, DEVICE_3,
                                                             false),
              UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

int main(int argc, char **argv) {
    InitGoogleTest(&argc, argv);
    AddGlobalTestEnvironment(new MockedLevelZeroTestEnvironment);
    return RUN_ALL_TESTS();
}
