// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#ifdef _WIN32
//workaround for std::numeric_limits on windows
#define NOMINMAX
#endif

#include <mutex>

#include <umf/providers/provider_level_zero.h>

#include "ipcFixtures.hpp"
#include "pool.hpp"
#include "utils_load_library.h"
#include "ze_api.h"

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

#if USE_DLOPEN
struct DlHandleCloser {
    void operator()(void *dlHandle) {
        if (dlHandle) {
            util_close_library(dlHandle);
        }
    }
};

std::unique_ptr<void, DlHandleCloser> zeDlHandle = nullptr;
void InitLevelZeroOps() {
#ifdef _WIN32
    const char *lib_name = "ze_loader.dll";
#else
    const char *lib_name = "libze_loader.so";
#endif
    // Load Level Zero symbols
    // NOTE that we use UMF_UTIL_OPEN_LIBRARY_GLOBAL which add all loaded symbols to the
    // global symbol table.
    zeDlHandle = std::unique_ptr<void, DlHandleCloser>(
        util_open_library(lib_name, UMF_UTIL_OPEN_LIBRARY_GLOBAL));
    *(void **)&libze_ops.zeInit =
        util_get_symbol_addr(zeDlHandle.get(), "zeInit", lib_name);
    ASSERT_NE(libze_ops.zeInit, nullptr);
    *(void **)&libze_ops.zeDriverGet =
        util_get_symbol_addr(zeDlHandle.get(), "zeDriverGet", lib_name);
    ASSERT_NE(libze_ops.zeDriverGet, nullptr);
    *(void **)&libze_ops.zeDeviceGet =
        util_get_symbol_addr(zeDlHandle.get(), "zeDeviceGet", lib_name);
    ASSERT_NE(libze_ops.zeDeviceGet, nullptr);
    *(void **)&libze_ops.zeDeviceGetProperties = util_get_symbol_addr(
        zeDlHandle.get(), "zeDeviceGetProperties", lib_name);
    ASSERT_NE(libze_ops.zeDeviceGetProperties, nullptr);
    *(void **)&libze_ops.zeContextCreate =
        util_get_symbol_addr(zeDlHandle.get(), "zeContextCreate", lib_name);
    ASSERT_NE(libze_ops.zeContextCreate, nullptr);
    *(void **)&libze_ops.zeContextDestroy =
        util_get_symbol_addr(zeDlHandle.get(), "zeContextDestroy", lib_name);
    ASSERT_NE(libze_ops.zeContextDestroy, nullptr);
    *(void **)&libze_ops.zeCommandQueueCreate = util_get_symbol_addr(
        zeDlHandle.get(), "zeCommandQueueCreate", lib_name);
    ASSERT_NE(libze_ops.zeCommandQueueCreate, nullptr);
    *(void **)&libze_ops.zeCommandQueueDestroy = util_get_symbol_addr(
        zeDlHandle.get(), "zeCommandQueueDestroy", lib_name);
    ASSERT_NE(libze_ops.zeCommandQueueDestroy, nullptr);
    *(void **)&libze_ops.zeCommandQueueExecuteCommandLists =
        util_get_symbol_addr(zeDlHandle.get(),
                             "zeCommandQueueExecuteCommandLists", lib_name);
    ASSERT_NE(libze_ops.zeCommandQueueExecuteCommandLists, nullptr);
    *(void **)&libze_ops.zeCommandQueueSynchronize = util_get_symbol_addr(
        zeDlHandle.get(), "zeCommandQueueSynchronize", lib_name);
    ASSERT_NE(libze_ops.zeCommandQueueSynchronize, nullptr);
    *(void **)&libze_ops.zeCommandListCreate =
        util_get_symbol_addr(zeDlHandle.get(), "zeCommandListCreate", lib_name);
    ASSERT_NE(libze_ops.zeCommandListCreate, nullptr);
    *(void **)&libze_ops.zeCommandListDestroy = util_get_symbol_addr(
        zeDlHandle.get(), "zeCommandListDestroy", lib_name);
    ASSERT_NE(libze_ops.zeCommandListDestroy, nullptr);
    *(void **)&libze_ops.zeCommandListClose =
        util_get_symbol_addr(zeDlHandle.get(), "zeCommandListClose", lib_name);
    ASSERT_NE(libze_ops.zeCommandListClose, nullptr);
    *(void **)&libze_ops.zeCommandListAppendMemoryCopy = util_get_symbol_addr(
        zeDlHandle.get(), "zeCommandListAppendMemoryCopy", lib_name);
    ASSERT_NE(libze_ops.zeCommandListAppendMemoryCopy, nullptr);
    *(void **)&libze_ops.zeCommandListAppendMemoryFill = util_get_symbol_addr(
        zeDlHandle.get(), "zeCommandListAppendMemoryFill", lib_name);
    ASSERT_NE(libze_ops.zeCommandListAppendMemoryFill, nullptr);
    *(void **)&libze_ops.zeMemGetAllocProperties = util_get_symbol_addr(
        zeDlHandle.get(), "zeMemGetAllocProperties", lib_name);
    ASSERT_NE(libze_ops.zeMemGetAllocProperties, nullptr);
    *(void **)&libze_ops.zeMemAllocDevice =
        util_get_symbol_addr(zeDlHandle.get(), "zeMemAllocDevice", lib_name);
    ASSERT_NE(libze_ops.zeMemAllocDevice, nullptr);
    *(void **)&libze_ops.zeMemFree =
        util_get_symbol_addr(zeDlHandle.get(), "zeMemFree", lib_name);
    ASSERT_NE(libze_ops.zeMemFree, nullptr);
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
#endif // USE_DLOPEN

std::once_flag level_zero_init_flag;
ze_result_t zeInitResult;
ze_result_t InitLevelZero() {
    std::call_once(level_zero_init_flag, []() {
        InitLevelZeroOps();
        zeInitResult = libze_ops.zeInit(0);
    });
    return zeInitResult;
}

ze_result_t CreateContext(ze_driver_handle_t hDriver,
                          ze_context_handle_t &hContext) {
    ze_context_desc_t ctxtDesc = {ZE_STRUCTURE_TYPE_CONTEXT_DESC, nullptr, 0};
    return libze_ops.zeContextCreate(hDriver, &ctxtDesc, &hContext);
}

ze_result_t FindDriverWithGpu(ze_driver_handle_t &hDriver,
                              ze_device_handle_t &hDevice) {
    // Discover all the driver instances
    uint32_t driverCount = 0;
    ze_result_t ze_result = libze_ops.zeDriverGet(&driverCount, nullptr);
    if (ze_result != ZE_RESULT_SUCCESS) {
        return ze_result;
    }

    std::vector<ze_driver_handle_t> allDrivers(driverCount);
    ze_result = libze_ops.zeDriverGet(&driverCount, allDrivers.data());
    if (ze_result != ZE_RESULT_SUCCESS) {
        return ze_result;
    }

    // Find a driver instance with a GPU device
    for (uint32_t i = 0; i < driverCount; ++i) {
        uint32_t deviceCount = 0;
        ze_result = libze_ops.zeDeviceGet(allDrivers[i], &deviceCount, nullptr);
        if (ze_result != ZE_RESULT_SUCCESS) {
            return ze_result;
        }

        std::vector<ze_device_handle_t> allDevices(deviceCount);
        ze_result = libze_ops.zeDeviceGet(allDrivers[i], &deviceCount,
                                          allDevices.data());
        if (ze_result != ZE_RESULT_SUCCESS) {
            return ze_result;
        }

        for (uint32_t d = 0; d < deviceCount; ++d) {
            ze_device_properties_t device_properties{};
            device_properties.stype = ZE_STRUCTURE_TYPE_DEVICE_PROPERTIES;
            ze_result = libze_ops.zeDeviceGetProperties(allDevices[d],
                                                        &device_properties);
            if (ze_result != ZE_RESULT_SUCCESS) {
                return ze_result;
            }

            if (ZE_DEVICE_TYPE_GPU == device_properties.type) {
                hDriver = allDrivers[i];
                hDevice = allDevices[d];
                return ze_result;
            }
        }
    }

    return ze_result;
}

class LevelZeroMemoryAccessor : public MemoryAccessor {
  public:
    LevelZeroMemoryAccessor(ze_context_handle_t hContext,
                            ze_device_handle_t hDevice)
        : hDevice_(hDevice), hContext_(hContext) {}
    void fill(void *ptr, size_t size, const void *pattern,
              size_t pattern_size) {
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
            hContext_, hDevice_, &commandQueueDesc, &hCommandQueue);
        ASSERT_EQ(ze_result, ZE_RESULT_SUCCESS);

        ze_command_list_handle_t hCommandList;
        ze_result = libze_ops.zeCommandListCreate(
            hContext_, hDevice_, &commandListDesc, &hCommandList);
        ASSERT_EQ(ze_result, ZE_RESULT_SUCCESS);

        // fill memory with a pattern
        ze_result = libze_ops.zeCommandListAppendMemoryFill(
            hCommandList, ptr, pattern, pattern_size, size, nullptr, 0,
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

    void copy(void *dst_ptr, void *src_ptr, size_t size) {
        ASSERT_NE(dst_ptr, nullptr);
        ASSERT_NE(src_ptr, nullptr);

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
            hContext_, hDevice_, &commandQueueDesc, &hCommandQueue);
        ASSERT_EQ(ze_result, ZE_RESULT_SUCCESS);

        ze_command_list_handle_t hCommandList;
        ze_result = libze_ops.zeCommandListCreate(
            hContext_, hDevice_, &commandListDesc, &hCommandList);
        ASSERT_EQ(ze_result, ZE_RESULT_SUCCESS);

        // copy from device memory to host memory
        libze_ops.zeCommandListAppendMemoryCopy(hCommandList, dst_ptr, src_ptr,
                                                size, nullptr, 0, nullptr);

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

  private:
    ze_device_handle_t hDevice_;
    ze_context_handle_t hContext_;
};

using LevelZeroProviderTestParams =
    std::tuple<level_zero_memory_provider_params_t, MemoryAccessor *>;

struct umfLevelZeroProviderTest
    : umf_test::test,
      ::testing::WithParamInterface<LevelZeroProviderTestParams> {

    void SetUp() override {
        test::SetUp();

        auto [l0_params, accessor] = this->GetParam();
        params = l0_params;
        hDevice = (ze_device_handle_t)params.level_zero_device_handle;
        hContext = (ze_context_handle_t)params.level_zero_context_handle;

        ASSERT_NE(hDevice, nullptr);
        ASSERT_NE(hContext, nullptr);

        switch (params.memory_type) {
        case UMF_MEMORY_TYPE_DEVICE:
            zeMemoryTypeExpected = ZE_MEMORY_TYPE_DEVICE;
            break;
        case UMF_MEMORY_TYPE_SHARED:
            zeMemoryTypeExpected = ZE_MEMORY_TYPE_SHARED;
            break;
        case UMF_MEMORY_TYPE_HOST:
            zeMemoryTypeExpected = ZE_MEMORY_TYPE_HOST;
            break;
        case UMF_MEMORY_TYPE_UNKNOWN:
            zeMemoryTypeExpected = ZE_MEMORY_TYPE_UNKNOWN;
            break;
        }

        ASSERT_NE(zeMemoryTypeExpected, ZE_MEMORY_TYPE_UNKNOWN);

        memAccessor = accessor;
    }

    void TearDown() override {
        ze_result_t ze_result = libze_ops.zeContextDestroy(hContext);
        ASSERT_EQ(ze_result, ZE_RESULT_SUCCESS);
        test::TearDown();
    }

    level_zero_memory_provider_params_t params;
    ze_device_handle_t hDevice = nullptr;
    ze_context_handle_t hContext = nullptr;
    ze_memory_type_t zeMemoryTypeExpected = ZE_MEMORY_TYPE_UNKNOWN;
    MemoryAccessor *memAccessor = nullptr;
};

GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfLevelZeroProviderTest);

TEST_P(umfLevelZeroProviderTest, basic) {
    const size_t size = 1024 * 8;
    const uint32_t pattern = 0xAB;

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
    memAccessor->fill(ptr, size, &pattern, sizeof(pattern));

    // get properties of the allocation
    ze_memory_allocation_properties_t alloc_props{
        ZE_STRUCTURE_TYPE_MEMORY_ALLOCATION_PROPERTIES, 0,
        ZE_MEMORY_TYPE_UNKNOWN, 0, 0};
    libze_ops.zeMemGetAllocProperties(hContext, ptr, &alloc_props, &hDevice);
    ASSERT_EQ(alloc_props.type, zeMemoryTypeExpected);

    // check if the pattern was successfully applied
    uint32_t *hostMemory = (uint32_t *)calloc(1, size);
    memAccessor->copy(hostMemory, ptr, size);
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

level_zero_memory_provider_params_t
CreateLevelZeroProviderParams(umf_usm_memory_type_t memory_type) {
    level_zero_memory_provider_params_t params = {NULL, NULL,
                                                  UMF_MEMORY_TYPE_UNKNOWN};
    ze_driver_handle_t hDriver;
    ze_device_handle_t hDevice;
    ze_context_handle_t hContext;

    ze_result_t ze_result = InitLevelZero();
    if (ze_result != ZE_RESULT_SUCCESS) {
        // Return empty params. Test will be skipped.
        return params;
    }

    ze_result = FindDriverWithGpu(hDriver, hDevice);
    if (ze_result != ZE_RESULT_SUCCESS) {
        // Return empty params. Test will be skipped.
        return params;
    }

    ze_result = CreateContext(hDriver, hContext);
    if (ze_result != ZE_RESULT_SUCCESS) {
        // Return empty params. Test will be skipped.
        return params;
    }

    params.level_zero_context_handle = hContext;
    params.level_zero_device_handle = hDevice;
    params.memory_type = memory_type;

    return params;
}

level_zero_memory_provider_params_t l0Params_device_memory =
    CreateLevelZeroProviderParams(UMF_MEMORY_TYPE_DEVICE);
level_zero_memory_provider_params_t l0Params_shared_memory =
    CreateLevelZeroProviderParams(UMF_MEMORY_TYPE_SHARED);
level_zero_memory_provider_params_t l0Params_host_memory =
    CreateLevelZeroProviderParams(UMF_MEMORY_TYPE_HOST);

LevelZeroMemoryAccessor l0Accessor(
    (ze_context_handle_t)l0Params_device_memory.level_zero_context_handle,
    (ze_device_handle_t)l0Params_device_memory.level_zero_device_handle);

HostMemoryAccessor hostAccessor;

INSTANTIATE_TEST_SUITE_P(
    umfLevelZeroProviderTestSuite, umfLevelZeroProviderTest,
    ::testing::Values(
        LevelZeroProviderTestParams{l0Params_device_memory, &l0Accessor},
        LevelZeroProviderTestParams{l0Params_shared_memory, &hostAccessor},
        LevelZeroProviderTestParams{l0Params_host_memory, &hostAccessor}));

// TODO: it looks like there is some problem with IPC implementation in Level
// Zero on windows. Issue: #494
#ifdef _WIN32
GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfIpcTest);
#else
INSTANTIATE_TEST_SUITE_P(umfLevelZeroProviderTestSuite, umfIpcTest,
                         ::testing::Values(ipcTestParams{
                             umfProxyPoolOps(), nullptr,
                             umfLevelZeroMemoryProviderOps(),
                             &l0Params_device_memory, &l0Accessor}));
#endif
