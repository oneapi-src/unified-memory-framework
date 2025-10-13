/*
 *
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_TEST_PROVIDER_LEVEL_ZERO_MOCKS_H
#define UMF_TEST_PROVIDER_LEVEL_ZERO_MOCKS_H

#include <gmock/gmock.h>
#include <vector>

#include "utils_log.h"
#include "ze_loopback.h"

// TEST CREATE methods for objects

template <class T> constexpr T TestCreatePointer(uintptr_t modifier = 0) {
    return reinterpret_cast<T>(static_cast<uintptr_t>(0x1000) + modifier);
}

ze_device_properties_t TestCreateDeviceProperties();

ze_memory_allocation_properties_t
TestCreateMemoryAllocationProperties(uint32_t modifier = 0);

// already created common instances for tests writing convenience

static const auto DEVICE_0 = TestCreatePointer<ze_device_handle_t>(0);
static const auto DEVICE_1 = TestCreatePointer<ze_device_handle_t>(1);
static const auto DEVICE_2 = TestCreatePointer<ze_device_handle_t>(2);
static const auto DEVICE_3 = TestCreatePointer<ze_device_handle_t>(3);
static const auto DEVICE_4 = TestCreatePointer<ze_device_handle_t>(4);
static const auto DEVICE_5 = TestCreatePointer<ze_device_handle_t>(5);

static const auto CONTEXT = TestCreatePointer<ze_context_handle_t>();
static const auto DEVICE_PROPS = TestCreateDeviceProperties();
static const auto MEM_PROPS = TestCreateMemoryAllocationProperties();

static void *POINTER_0 = TestCreatePointer<void *>(0x90);
static void *POINTER_1 = TestCreatePointer<void *>(0x91);
static void *POINTER_2 = TestCreatePointer<void *>(0x92);
static void *POINTER_3 = TestCreatePointer<void *>(0x93);
static void *POINTER_4 = TestCreatePointer<void *>(0x94);

class LevelZeroMock : public LevelZero {
  public:
    MOCK_METHOD3(zeContextCreate,
                 ze_result_t(ze_driver_handle_t, const ze_context_desc_t *,
                             ze_context_handle_t *));
    MOCK_METHOD2(zeDeviceGetProperties,
                 ze_result_t(ze_device_handle_t, ze_device_properties_t *));
    MOCK_METHOD6(zeMemAllocDevice,
                 ze_result_t(ze_context_handle_t,
                             const ze_device_mem_alloc_desc_t *, size_t, size_t,
                             ze_device_handle_t, void **));
    MOCK_METHOD4(zeMemGetAllocProperties,
                 ze_result_t(ze_context_handle_t, const void *,
                             ze_memory_allocation_properties_t *,
                             ze_device_handle_t *));
    MOCK_METHOD4(zeContextMakeMemoryResident,
                 ze_result_t(ze_context_handle_t, ze_device_handle_t, void *,
                             size_t));
    MOCK_METHOD4(zeContextEvictMemory,
                 ze_result_t(ze_context_handle_t, ze_device_handle_t, void *,
                             size_t));
    MOCK_METHOD2(zeMemFree,
                 ze_result_t(ze_context_handle_t hContext, void *ptr));

    // A helper function that (1) sets all EXPECT_CALLs related to successful l0 provider creation
    // and initialization (2) calls l0 provider creation and initialization
    umf_memory_provider_handle_t initializeMemoryProviderWithResidentDevices(
        ze_device_handle_t device,
        std::vector<ze_device_handle_t> residentDevices,
        ze_context_handle_t context = CONTEXT,
        ze_device_properties_t device_properties = DEVICE_PROPS,
        ze_memory_allocation_properties_t memory_allocation_properties =
            MEM_PROPS);
};

// important, makes UMF load ze_loopback instead of regular l0
class MockedLevelZeroTestEnvironment : public ::testing::Environment {

    void *lib_handle;

  public:
    static LevelZero **l0interface;

    void SetUp() override;
    void TearDown() override;
};

#endif //UMF_TEST_PROVIDER_LEVEL_ZERO_MOCKS_H
