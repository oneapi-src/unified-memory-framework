/*
 *
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <cstdlib>
#include <iostream>

#include "ze_loopback.h"

ZE_APIEXPORT LevelZero *level_zero_mock = nullptr;

static void check_mock_present() {
    if (level_zero_mock == nullptr) {
        std::cerr << "level_zero_mock was not set\n";
        abort();
    }
}

#define FAIL_NOT_IMPLEMENTED                                                   \
    std::cerr << __func__ << " not implemented in ze_loopback.cpp\n";          \
    abort();

//
// libze_ops from src/utils/utils_level_zero.cpp
//

ZE_APIEXPORT ze_result_t ZE_APICALL zeInit(ze_init_flags_t flags) {
    (void)flags;
    return ZE_RESULT_SUCCESS;
}

ZE_APIEXPORT ze_result_t ZE_APICALL zeDriverGet(uint32_t *pCount,
                                                ze_driver_handle_t *phDrivers) {
    (void)phDrivers;
    (void)pCount;
    FAIL_NOT_IMPLEMENTED
}

ZE_APIEXPORT ze_result_t ZE_APICALL zeDeviceGet(ze_driver_handle_t hDriver,
                                                uint32_t *pCount,
                                                ze_device_handle_t *phDevices) {
    (void)hDriver;
    (void)pCount;
    (void)phDevices;
    FAIL_NOT_IMPLEMENTED
}

ZE_APIEXPORT ze_result_t ZE_APICALL zeDeviceGetProperties(
    ze_device_handle_t hDevice, ze_device_properties_t *pDeviceProperties) {
    check_mock_present();
    return level_zero_mock->zeDeviceGetProperties(hDevice, pDeviceProperties);
}

ZE_APIEXPORT ze_result_t ZE_APICALL
zeContextCreate(ze_driver_handle_t hDriver, const ze_context_desc_t *desc,
                ze_context_handle_t *phContext) {
    (void)hDriver;
    (void)desc;
    (void)phContext;
    FAIL_NOT_IMPLEMENTED
}

ZE_APIEXPORT ze_result_t ZE_APICALL
zeContextDestroy(ze_context_handle_t hContext) {
    (void)hContext;
    FAIL_NOT_IMPLEMENTED;
}

ZE_APIEXPORT ze_result_t ZE_APICALL
zeCommandQueueCreate(ze_context_handle_t hContext, ze_device_handle_t hDevice,
                     const ze_command_queue_desc_t *desc,
                     ze_command_queue_handle_t *phCommandQueue) {
    (void)hContext;
    (void)hDevice;
    (void)desc;
    (void)phCommandQueue;
    FAIL_NOT_IMPLEMENTED
}

ZE_APIEXPORT ze_result_t ZE_APICALL
zeCommandQueueDestroy(ze_command_queue_handle_t hCommandQueue) {
    (void)hCommandQueue;
    FAIL_NOT_IMPLEMENTED
}

ZE_APIEXPORT ze_result_t ZE_APICALL zeCommandQueueExecuteCommandLists(
    ze_command_queue_handle_t hCommandQueue, uint32_t numCommandLists,
    ze_command_list_handle_t *phCommandLists, ze_fence_handle_t hFence) {
    (void)hCommandQueue;
    (void)numCommandLists;
    (void)phCommandLists;
    (void)hFence;
    FAIL_NOT_IMPLEMENTED
}

ZE_APIEXPORT ze_result_t ZE_APICALL zeCommandQueueSynchronize(
    ze_command_queue_handle_t hCommandQueue, uint64_t timeout) {
    (void)hCommandQueue;
    (void)timeout;
    FAIL_NOT_IMPLEMENTED
}

ZE_APIEXPORT ze_result_t ZE_APICALL
zeCommandListCreate(ze_context_handle_t hContext, ze_device_handle_t hDevice,
                    const ze_command_list_desc_t *desc,
                    ze_command_list_handle_t *phCommandList) {
    (void)hContext;
    (void)hDevice;
    (void)desc;
    (void)phCommandList;
    FAIL_NOT_IMPLEMENTED
}

ZE_APIEXPORT ze_result_t ZE_APICALL
zeCommandListDestroy(ze_command_list_handle_t hCommandList) {
    (void)hCommandList;
    FAIL_NOT_IMPLEMENTED
}

ZE_APIEXPORT ze_result_t ZE_APICALL
zeCommandListClose(ze_command_list_handle_t hCommandList) {
    (void)hCommandList;
    FAIL_NOT_IMPLEMENTED
}

ZE_APIEXPORT ze_result_t ZE_APICALL zeCommandListAppendMemoryCopy(
    ze_command_list_handle_t hCommandList, void *dstptr, const void *srcptr,
    size_t size, ze_event_handle_t hSignalEvent, uint32_t numWaitEvents,
    ze_event_handle_t *phWaitEvents) {
    (void)hCommandList;
    (void)dstptr;
    (void)srcptr;
    (void)size;
    (void)hSignalEvent;
    (void)numWaitEvents;
    (void)phWaitEvents;
    FAIL_NOT_IMPLEMENTED
}

ZE_APIEXPORT ze_result_t ZE_APICALL zeCommandListAppendMemoryFill(
    ze_command_list_handle_t hCommandList, void *ptr, const void *pattern,
    size_t pattern_size, size_t size, ze_event_handle_t hSignalEvent,
    uint32_t numWaitEvents, ze_event_handle_t *phWaitEvents) {
    (void)hCommandList;
    (void)ptr;
    (void)pattern;
    (void)pattern_size;
    (void)size;
    (void)hSignalEvent;
    (void)numWaitEvents;
    (void)phWaitEvents;
    FAIL_NOT_IMPLEMENTED
}

ZE_APIEXPORT ze_result_t ZE_APICALL
zeMemGetAllocProperties(ze_context_handle_t hContext, const void *ptr,
                        ze_memory_allocation_properties_t *pMemAllocProperties,
                        ze_device_handle_t *phDevice) {
    check_mock_present();
    return level_zero_mock->zeMemGetAllocProperties(
        hContext, ptr, pMemAllocProperties, phDevice);
}

ZE_APIEXPORT ze_result_t ZE_APICALL zeMemAllocDevice(
    ze_context_handle_t hContext, const ze_device_mem_alloc_desc_t *device_desc,
    size_t size, size_t alignment, ze_device_handle_t hDevice, void **pptr) {
    check_mock_present();
    return level_zero_mock->zeMemAllocDevice(hContext, device_desc, size,
                                             alignment, hDevice, pptr);
}

ZE_APIEXPORT ze_result_t ZE_APICALL zeMemFree(ze_context_handle_t hContext,
                                              void *ptr) {
    check_mock_present();
    return level_zero_mock->zeMemFree(hContext, ptr);
}

ZE_APIEXPORT ze_result_t ZE_APICALL
zeDeviceGetMemoryProperties(ze_device_handle_t hDevice, uint32_t *pCount,
                            ze_device_memory_properties_t *pMemProperties) {
    (void)hDevice;
    (void)pCount;
    (void)pMemProperties;
    FAIL_NOT_IMPLEMENTED
}

//
// ze_ops_t operations from src/provider/provider_level_zero.c
//

ze_result_t ZE_APICALL zeMemAllocHost(ze_context_handle_t hContext,
                                      const ze_host_mem_alloc_desc_t *host_desc,
                                      size_t size, size_t alignment,
                                      void **pptr) {
    (void)hContext;
    (void)host_desc;
    (void)size;
    (void)alignment;
    (void)pptr;
    FAIL_NOT_IMPLEMENTED
}

ze_result_t ZE_APICALL zeMemAllocShared(
    ze_context_handle_t hContext, const ze_device_mem_alloc_desc_t *device_desc,
    const ze_host_mem_alloc_desc_t *host_desc, size_t size, size_t alignment,
    ze_device_handle_t hDevice, void **pptr) {
    (void)hContext;
    (void)device_desc;
    (void)host_desc;
    (void)size;
    (void)alignment;
    (void)hDevice;
    (void)pptr;
    FAIL_NOT_IMPLEMENTED
}

ze_result_t ZE_APICALL zeMemGetIpcHandle(ze_context_handle_t hContext,
                                         const void *ptr,
                                         ze_ipc_mem_handle_t *pIpcHandle) {
    (void)hContext;
    (void)ptr;
    (void)pIpcHandle;
    FAIL_NOT_IMPLEMENTED
}

ze_result_t ZE_APICALL zeMemPutIpcHandle(ze_context_handle_t hContext,
                                         ze_ipc_mem_handle_t handle) {
    (void)hContext;
    (void)handle;
    FAIL_NOT_IMPLEMENTED
}

ze_result_t ZE_APICALL zeMemOpenIpcHandle(ze_context_handle_t hContext,
                                          ze_device_handle_t hDevice,
                                          ze_ipc_mem_handle_t handle,
                                          ze_ipc_memory_flags_t flags,
                                          void **pptr) {
    (void)hContext;
    (void)hDevice;
    (void)handle;
    (void)flags;
    (void)pptr;
    FAIL_NOT_IMPLEMENTED
}

ze_result_t ZE_APICALL zeMemCloseIpcHandle(ze_context_handle_t hContext,
                                           const void *ptr) {
    (void)hContext;
    (void)ptr;
    FAIL_NOT_IMPLEMENTED
}

ze_result_t ZE_APICALL zeContextMakeMemoryResident(ze_context_handle_t hContext,
                                                   ze_device_handle_t hDevice,
                                                   void *ptr, size_t size) {
    check_mock_present();
    return level_zero_mock->zeContextMakeMemoryResident(hContext, hDevice, ptr,
                                                        size);
}

ze_result_t ZE_APICALL zeContextEvictMemory(ze_context_handle_t hContext,
                                            ze_device_handle_t hDevice,
                                            void *ptr, size_t size) {
    check_mock_present();
    return level_zero_mock->zeContextEvictMemory(hContext, hDevice, ptr, size);
}

ze_result_t ZE_APICALL
zeMemFreeExt(ze_context_handle_t hContext,
             const ze_memory_free_ext_desc_t *pMemFreeDesc, void *ptr) {
    (void)hContext;
    (void)pMemFreeDesc;
    (void)ptr;
    FAIL_NOT_IMPLEMENTED
}
