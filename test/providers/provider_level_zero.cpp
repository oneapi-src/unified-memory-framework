// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <dlfcn.h>
#include <level_zero/ze_api.h>

#include "pool.hpp"
#include "umf/providers/provider_level_zero.h"

using umf_test::test;
using namespace umf_test;

struct libze_ops {
    ze_result_t (*zeInit)(ze_init_flags_t flags);
    ze_result_t (*zeDriverGet)(uint32_t *pCount, ze_driver_handle_t *phDrivers);
    ze_result_t (*zeDeviceGet)(ze_driver_handle_t hDriver, uint32_t *pCount,
                               ze_device_handle_t *phDevices);
    ze_result_t (*zeDeviceGetProperties)(
        ze_device_handle_t hDevice, ze_device_properties_t *pDeviceProperties);

    ze_result_t (*zeContextCreate)(ze_driver_handle_t hDriver,
                                   const ze_context_desc_t *desc,
                                   ze_context_handle_t *phContext);
    ze_result_t (*zeContextDestroy)(ze_context_handle_t hContext);
    ze_result_t (*zeCommandQueueCreate)(
        ze_context_handle_t hContext, ze_device_handle_t hDevice,
        const ze_command_queue_desc_t *desc,
        ze_command_queue_handle_t *phCommandQueue);
    ze_result_t (*zeCommandQueueDestroy)(
        ze_command_queue_handle_t hCommandQueue);
    ze_result_t (*zeCommandQueueExecuteCommandLists)(
        ze_command_queue_handle_t hCommandQueue, uint32_t numCommandLists,
        ze_command_list_handle_t *phCommandLists, ze_fence_handle_t hFence);
    ze_result_t (*zeCommandQueueSynchronize)(
        ze_command_queue_handle_t hCommandQueue, uint64_t timeout);
    ze_result_t (*zeCommandListCreate)(ze_context_handle_t hContext,
                                       ze_device_handle_t hDevice,
                                       const ze_command_list_desc_t *desc,
                                       ze_command_list_handle_t *phCommandList);
    ze_result_t (*zeCommandListDestroy)(ze_command_list_handle_t hCommandList);
    ze_result_t (*zeCommandListClose)(ze_command_list_handle_t hCommandList);
    ze_result_t (*zeCommandListAppendMemoryCopy)(
        ze_command_list_handle_t hCommandList, void *dstptr, const void *srcptr,
        size_t size, ze_event_handle_t hSignalEvent, uint32_t numWaitEvents,
        ze_event_handle_t *phWaitEvents);
    ze_result_t (*zeCommandListAppendMemoryFill)(
        ze_command_list_handle_t hCommandList, void *ptr, const void *pattern,
        size_t pattern_size, size_t size, ze_event_handle_t hSignalEvent,
        uint32_t numWaitEvents, ze_event_handle_t *phWaitEvents);
    ze_result_t (*zeMemGetAllocProperties)(
        ze_context_handle_t hContext, const void *ptr,
        ze_memory_allocation_properties_t *pMemAllocProperties,
        ze_device_handle_t *phDevice);
    ze_result_t (*zeMemAllocDevice)(ze_context_handle_t,
                                    const ze_device_mem_alloc_desc_t *, size_t,
                                    size_t, ze_device_handle_t, void **);
    ze_result_t (*zeMemFree)(ze_context_handle_t, void *);
} libze_ops;

struct umfLevelZeroProviderTest : umf_test::test {

#if USE_DLOPEN
    void InitLevelZeroOps() {
        // Load Level Zero symbols
        // NOTE that we use RTLD_GLOBAL which add all loaded symbols to the
        // global symbol table. These symbols would be used by the Level Zero
        // provider later
        zeDlHandle = dlopen("libze_loader.so", RTLD_GLOBAL | RTLD_LAZY);

        *(void **)&libze_ops.zeInit = dlsym(zeDlHandle, "zeInit");
        ASSERT_NE(libze_ops.zeInit, nullptr);
        *(void **)&libze_ops.zeDriverGet = dlsym(zeDlHandle, "zeDriverGet");
        ASSERT_NE(libze_ops.zeDriverGet, nullptr);
        *(void **)&libze_ops.zeDeviceGet = dlsym(zeDlHandle, "zeDeviceGet");
        ASSERT_NE(libze_ops.zeDeviceGet, nullptr);
        *(void **)&libze_ops.zeDeviceGetProperties =
            dlsym(zeDlHandle, "zeDeviceGetProperties");
        ASSERT_NE(libze_ops.zeDeviceGetProperties, nullptr);
        *(void **)&libze_ops.zeContextCreate =
            dlsym(zeDlHandle, "zeContextCreate");
        ASSERT_NE(libze_ops.zeContextCreate, nullptr);
        *(void **)&libze_ops.zeContextDestroy =
            dlsym(zeDlHandle, "zeContextDestroy");
        ASSERT_NE(libze_ops.zeContextDestroy, nullptr);
        *(void **)&libze_ops.zeCommandQueueCreate =
            dlsym(zeDlHandle, "zeCommandQueueCreate");
        ASSERT_NE(libze_ops.zeCommandQueueCreate, nullptr);
        *(void **)&libze_ops.zeCommandQueueDestroy =
            dlsym(zeDlHandle, "zeCommandQueueDestroy");
        ASSERT_NE(libze_ops.zeCommandQueueDestroy, nullptr);
        *(void **)&libze_ops.zeCommandQueueExecuteCommandLists =
            dlsym(zeDlHandle, "zeCommandQueueExecuteCommandLists");
        ASSERT_NE(libze_ops.zeCommandQueueExecuteCommandLists, nullptr);
        *(void **)&libze_ops.zeCommandQueueSynchronize =
            dlsym(zeDlHandle, "zeCommandQueueSynchronize");
        ASSERT_NE(libze_ops.zeCommandQueueSynchronize, nullptr);
        *(void **)&libze_ops.zeCommandListCreate =
            dlsym(zeDlHandle, "zeCommandListCreate");
        ASSERT_NE(libze_ops.zeCommandListCreate, nullptr);
        *(void **)&libze_ops.zeCommandListDestroy =
            dlsym(zeDlHandle, "zeCommandListDestroy");
        ASSERT_NE(libze_ops.zeCommandListDestroy, nullptr);
        *(void **)&libze_ops.zeCommandListClose =
            dlsym(zeDlHandle, "zeCommandListClose");
        ASSERT_NE(libze_ops.zeCommandListClose, nullptr);
        *(void **)&libze_ops.zeCommandListAppendMemoryCopy =
            dlsym(zeDlHandle, "zeCommandListAppendMemoryCopy");
        ASSERT_NE(libze_ops.zeCommandListAppendMemoryCopy, nullptr);
        *(void **)&libze_ops.zeCommandListAppendMemoryFill =
            dlsym(zeDlHandle, "zeCommandListAppendMemoryFill");
        ASSERT_NE(libze_ops.zeCommandListAppendMemoryFill, nullptr);
        *(void **)&libze_ops.zeMemGetAllocProperties =
            dlsym(zeDlHandle, "zeMemGetAllocProperties");
        ASSERT_NE(libze_ops.zeMemGetAllocProperties, nullptr);
        *(void **)&libze_ops.zeMemAllocDevice =
            dlsym(zeDlHandle, "zeMemAllocDevice");
        ASSERT_NE(libze_ops.zeMemAllocDevice, nullptr);
        *(void **)&libze_ops.zeMemFree = dlsym(zeDlHandle, "zeMemFree");
        ASSERT_NE(libze_ops.zeMemFree, nullptr);
    }

    void DestroyLevelZeroOps() {
        // Just close the handle here
        dlclose(zeDlHandle);
    }
#else  // USE_DLOPEN
    void InitLevelZeroOps() {
        // Level Zero is linked statically but we prepare ops structure to
        // make test code consistent
        libze_ops.zeInit = zeInit;
        libze_ops.zeDriverGet = zeDriverGet;
        libze_ops.zeDeviceGet = zeDeviceGet;
        libze_ops.zeDeviceGetProperties = zeDeviceGetProperties;
        libze_ops.zeContextCreate = zeContextCreate;
        libze_ops.zeContextDestroy = zeContextDestroy;
        libze_ops.zeCommandQueueCreate = zeCommandQueueCreate;
        libze_ops.zeCommandQueueDestroy = zeCommandQueueDestroy;
        libze_ops.zeCommandQueueExecuteCommandLists =
            zeCommandQueueExecuteCommandLists;
        libze_ops.zeCommandQueueSynchronize = zeCommandQueueSynchronize;
        libze_ops.zeCommandListCreate = zeCommandListCreate;
        libze_ops.zeCommandListDestroy = zeCommandListDestroy;
        libze_ops.zeCommandListClose = zeCommandListClose;
        libze_ops.zeCommandListAppendMemoryCopy = zeCommandListAppendMemoryCopy;
        libze_ops.zeCommandListAppendMemoryFill = zeCommandListAppendMemoryFill;
        libze_ops.zeMemGetAllocProperties = zeMemGetAllocProperties;
        libze_ops.zeMemAllocDevice = zeMemAllocDevice;
        libze_ops.zeMemFree = zeMemFree;
    }

    void DestroyLevelZeroOps() {
        // NOP
    }
#endif // USE_DLOPEN

    void SetUp() override {
        test::SetUp();

        // Init the libze_ops structure
        InitLevelZeroOps();

        // Initialize the driver
        ze_result_t ze_result = libze_ops.zeInit(0);
        ASSERT_EQ(ze_result, ZE_RESULT_SUCCESS);

        // Discover all the driver instances
        uint32_t driverCount = 0;
        ze_result = libze_ops.zeDriverGet(&driverCount, nullptr);
        ASSERT_EQ(ze_result, ZE_RESULT_SUCCESS);
        ASSERT_GT(driverCount, 0);

        std::vector<ze_driver_handle_t> allDrivers(driverCount);
        ze_result = libze_ops.zeDriverGet(&driverCount, allDrivers.data());
        ASSERT_EQ(ze_result, ZE_RESULT_SUCCESS);

        // Find a driver instance with a GPU device
        for (uint32_t i = 0; i < driverCount; ++i) {
            ASSERT_NE(allDrivers[i], nullptr);

            uint32_t deviceCount = 0;
            ze_result =
                libze_ops.zeDeviceGet(allDrivers[i], &deviceCount, nullptr);
            ASSERT_EQ(ze_result, ZE_RESULT_SUCCESS);
            ASSERT_GT(deviceCount, 0);

            std::vector<ze_device_handle_t> allDevices(deviceCount);
            ze_result = libze_ops.zeDeviceGet(allDrivers[i], &deviceCount,
                                              allDevices.data());
            ASSERT_EQ(ze_result, ZE_RESULT_SUCCESS);

            for (uint32_t d = 0; d < deviceCount; ++d) {
                ASSERT_NE(allDevices[d], nullptr);

                ze_device_properties_t device_properties{};
                device_properties.stype = ZE_STRUCTURE_TYPE_DEVICE_PROPERTIES;
                ze_result = libze_ops.zeDeviceGetProperties(allDevices[d],
                                                            &device_properties);
                ASSERT_EQ(ze_result, ZE_RESULT_SUCCESS);

                if (ZE_DEVICE_TYPE_GPU == device_properties.type) {
                    hDriver = allDrivers[i];
                    hDevice = allDevices[d];
                    break;
                }
            }

            if (nullptr != hDriver) {
                break;
            }
        }

        if (nullptr == hDevice) {
            GTEST_SKIP() << "Test skipped, no GPU devices found";
        }

        // Create context
        ze_context_desc_t ctxtDesc = {ZE_STRUCTURE_TYPE_CONTEXT_DESC, nullptr,
                                      0};
        ze_result = libze_ops.zeContextCreate(hDriver, &ctxtDesc, &hContext);
        ASSERT_EQ(ze_result, ZE_RESULT_SUCCESS);
        ASSERT_NE(hContext, nullptr);
    }

    void TearDown() override {
        ze_result_t ze_result = libze_ops.zeContextDestroy(hContext);
        ASSERT_EQ(ze_result, ZE_RESULT_SUCCESS);
        DestroyLevelZeroOps();
        test::TearDown();
    }

    void InitDeviceMemory(void *ptr, int pattern, size_t size) {
        ASSERT_NE(ptr, nullptr);

        ze_command_queue_desc_t commandQueueDesc = {
            ZE_STRUCTURE_TYPE_COMMAND_QUEUE_DESC,
            NULL,
            0,
            0,
            0,
            ZE_COMMAND_QUEUE_MODE_DEFAULT,
            ZE_COMMAND_QUEUE_PRIORITY_NORMAL};

        ze_command_list_desc_t commandListDesc = {
            ZE_STRUCTURE_TYPE_COMMAND_LIST_DESC, 0, 0,
            ZE_COMMAND_LIST_FLAG_RELAXED_ORDERING};

        ze_command_queue_handle_t hCommandQueue;
        ze_result_t ze_result = libze_ops.zeCommandQueueCreate(
            hContext, hDevice, &commandQueueDesc, &hCommandQueue);
        ASSERT_EQ(ze_result, ZE_RESULT_SUCCESS);

        ze_command_list_handle_t hCommandList;
        ze_result = libze_ops.zeCommandListCreate(
            hContext, hDevice, &commandListDesc, &hCommandList);
        ASSERT_EQ(ze_result, ZE_RESULT_SUCCESS);

        // fill memory with a pattern
        ze_result = libze_ops.zeCommandListAppendMemoryFill(
            hCommandList, ptr, &pattern, sizeof(pattern), size, nullptr, 0,
            nullptr);
        ASSERT_EQ(ze_result, ZE_RESULT_SUCCESS);

        // close and execute the command list
        ze_result = libze_ops.zeCommandListClose(hCommandList);
        ASSERT_EQ(ze_result, ZE_RESULT_SUCCESS);
        ze_result = libze_ops.zeCommandQueueExecuteCommandLists(
            hCommandQueue, 1, &hCommandList, nullptr);
        ASSERT_EQ(ze_result, ZE_RESULT_SUCCESS);

        // sync
        ze_result = libze_ops.zeCommandQueueSynchronize(
            hCommandQueue, std::numeric_limits<uint64_t>::max());
        ASSERT_EQ(ze_result, ZE_RESULT_SUCCESS);

        // cleanup
        ze_result = libze_ops.zeCommandListDestroy(hCommandList);
        ASSERT_EQ(ze_result, ZE_RESULT_SUCCESS);
        ze_result = libze_ops.zeCommandQueueDestroy(hCommandQueue);
        ASSERT_EQ(ze_result, ZE_RESULT_SUCCESS);
    }

    void CopyDeviceToHostMemory(void *host_ptr, void *device_ptr, size_t size) {
        ASSERT_NE(host_ptr, nullptr);
        ASSERT_NE(device_ptr, nullptr);

        ze_command_queue_desc_t commandQueueDesc = {
            ZE_STRUCTURE_TYPE_COMMAND_QUEUE_DESC,
            NULL,
            0,
            0,
            0,
            ZE_COMMAND_QUEUE_MODE_DEFAULT,
            ZE_COMMAND_QUEUE_PRIORITY_NORMAL};

        ze_command_list_desc_t commandListDesc = {
            ZE_STRUCTURE_TYPE_COMMAND_LIST_DESC, 0, 0,
            ZE_COMMAND_LIST_FLAG_RELAXED_ORDERING};

        ze_command_queue_handle_t hCommandQueue;
        ze_result_t ze_result = libze_ops.zeCommandQueueCreate(
            hContext, hDevice, &commandQueueDesc, &hCommandQueue);
        ASSERT_EQ(ze_result, ZE_RESULT_SUCCESS);

        ze_command_list_handle_t hCommandList;
        ze_result = libze_ops.zeCommandListCreate(
            hContext, hDevice, &commandListDesc, &hCommandList);
        ASSERT_EQ(ze_result, ZE_RESULT_SUCCESS);

        // copy from device memory to host memory
        libze_ops.zeCommandListAppendMemoryCopy(
            hCommandList, host_ptr, device_ptr, size, nullptr, 0, nullptr);

        // close and execute the command list
        libze_ops.zeCommandListClose(hCommandList);
        libze_ops.zeCommandQueueExecuteCommandLists(hCommandQueue, 1,
                                                    &hCommandList, nullptr);

        libze_ops.zeCommandQueueSynchronize(
            hCommandQueue, std::numeric_limits<uint64_t>::max());

        // cleanup
        ze_result = libze_ops.zeCommandListDestroy(hCommandList);
        ASSERT_EQ(ze_result, ZE_RESULT_SUCCESS);
        ze_result = libze_ops.zeCommandQueueDestroy(hCommandQueue);
        ASSERT_EQ(ze_result, ZE_RESULT_SUCCESS);
    }

    ze_driver_handle_t hDriver;
    ze_device_handle_t hDevice;
    ze_context_handle_t hContext;
    void *zeDlHandle;
};

TEST_F(umfLevelZeroProviderTest, basic) {
    const size_t size = 1024 * 8;
    const uint32_t pattern = 0xAB;

    // setup params
    level_zero_memory_provider_params_t params = {0};
    params.level_zero_context_handle = hContext;
    params.level_zero_device_handle = hDevice;
    params.memory_type = UMF_MEMORY_TYPE_DEVICE;
    // create Level Zero provider
    umf_memory_provider_handle_t provider = nullptr;
    umf_result_t umf_result = umfMemoryProviderCreate(
        umfLevelZeroMemoryProviderOps(), &params, &provider);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(provider, nullptr);

    void *ptr = nullptr;
    umf_result = umfMemoryProviderAlloc(provider, size, 0, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    // use the allocated memory - fill it with a 0xAB pattern
    InitDeviceMemory(ptr, pattern, size);

    // get properties of the allocation
    ze_memory_allocation_properties_t alloc_props{
        ZE_STRUCTURE_TYPE_MEMORY_ALLOCATION_PROPERTIES, 0,
        ZE_MEMORY_TYPE_UNKNOWN, 0, 0};
    libze_ops.zeMemGetAllocProperties(hContext, ptr, &alloc_props, &hDevice);
    ASSERT_EQ(alloc_props.type, ZE_MEMORY_TYPE_DEVICE);

    // check if the pattern was successfully applied
    uint32_t *hostMemory = (uint32_t *)malloc(size);
    CopyDeviceToHostMemory(hostMemory, ptr, size);
    for (size_t i = 0; i < size / sizeof(int); i++) {
        ASSERT_EQ(hostMemory[i], pattern);
    }
    free(hostMemory);

    umf_result = umfMemoryProviderFree(provider, ptr, size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umfMemoryProviderDestroy(provider);
}

// TODO add Level Zero Memory Provider specyfic tests
// TODO add negative test and check for Level Zero native errors
// TODO add tests that mixes Level Zero Memory Provider and Disjoint Pool
