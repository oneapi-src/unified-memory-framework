/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "level_zero_helpers.h"

#include <memory>
#include <stdlib.h>

#include "utils_concurrency.h"
#include "utils_load_library.h"

#include "ze_api.h"

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
            utils_close_library(dlHandle);
        }
    }
};

std::unique_ptr<void, DlHandleCloser> zeDlHandle = nullptr;
int InitLevelZeroOps() {
#ifdef _WIN32
    const char *lib_name = "ze_loader.dll";
#else
    const char *lib_name = "libze_loader.so";
#endif
    // Load Level Zero symbols
    // NOTE that we use UMF_UTIL_OPEN_LIBRARY_GLOBAL which add all loaded symbols to the
    // global symbol table.
    zeDlHandle = std::unique_ptr<void, DlHandleCloser>(
        utils_open_library(lib_name, UMF_UTIL_OPEN_LIBRARY_GLOBAL));
    *(void **)&libze_ops.zeInit =
        utils_get_symbol_addr(zeDlHandle.get(), "zeInit", lib_name);
    if (libze_ops.zeInit == nullptr) {
        fprintf(stderr, "zeInit symbol not found in %s\n", lib_name);
        return -1;
    }
    *(void **)&libze_ops.zeDriverGet =
        utils_get_symbol_addr(zeDlHandle.get(), "zeDriverGet", lib_name);
    if (libze_ops.zeDriverGet == nullptr) {
        fprintf(stderr, "zeDriverGet symbol not found in %s\n", lib_name);
        return -1;
    }
    *(void **)&libze_ops.zeDeviceGet =
        utils_get_symbol_addr(zeDlHandle.get(), "zeDeviceGet", lib_name);
    if (libze_ops.zeDeviceGet == nullptr) {
        fprintf(stderr, "zeDeviceGet symbol not found in %s\n", lib_name);
        return -1;
    }
    *(void **)&libze_ops.zeDeviceGetProperties = utils_get_symbol_addr(
        zeDlHandle.get(), "zeDeviceGetProperties", lib_name);
    if (libze_ops.zeDeviceGetProperties == nullptr) {
        fprintf(stderr, "zeDeviceGetProperties symbol not found in %s\n",
                lib_name);
        return -1;
    }
    *(void **)&libze_ops.zeContextCreate =
        utils_get_symbol_addr(zeDlHandle.get(), "zeContextCreate", lib_name);
    if (libze_ops.zeContextCreate == nullptr) {
        fprintf(stderr, "zeContextCreate symbol not found in %s\n", lib_name);
        return -1;
    }
    *(void **)&libze_ops.zeContextDestroy =
        utils_get_symbol_addr(zeDlHandle.get(), "zeContextDestroy", lib_name);
    if (libze_ops.zeContextDestroy == nullptr) {
        fprintf(stderr, "zeContextDestroy symbol not found in %s\n", lib_name);
        return -1;
    }
    *(void **)&libze_ops.zeCommandQueueCreate = utils_get_symbol_addr(
        zeDlHandle.get(), "zeCommandQueueCreate", lib_name);
    if (libze_ops.zeCommandQueueCreate == nullptr) {
        fprintf(stderr, "zeCommandQueueCreate symbol not found in %s\n",
                lib_name);
        return -1;
    }
    *(void **)&libze_ops.zeCommandQueueDestroy = utils_get_symbol_addr(
        zeDlHandle.get(), "zeCommandQueueDestroy", lib_name);
    if (libze_ops.zeCommandQueueDestroy == nullptr) {
        fprintf(stderr, "zeCommandQueueDestroy symbol not found in %s\n",
                lib_name);
        return -1;
    }
    *(void **)&libze_ops.zeCommandQueueExecuteCommandLists =
        utils_get_symbol_addr(zeDlHandle.get(),
                              "zeCommandQueueExecuteCommandLists", lib_name);
    if (libze_ops.zeCommandQueueExecuteCommandLists == nullptr) {
        fprintf(stderr,
                "zeCommandQueueExecuteCommandLists symbol not found in %s\n",
                lib_name);
        return -1;
    }
    *(void **)&libze_ops.zeCommandQueueSynchronize = utils_get_symbol_addr(
        zeDlHandle.get(), "zeCommandQueueSynchronize", lib_name);
    if (libze_ops.zeCommandQueueSynchronize == nullptr) {
        fprintf(stderr, "zeCommandQueueSynchronize symbol not found in %s\n",
                lib_name);
        return -1;
    }
    *(void **)&libze_ops.zeCommandListCreate = utils_get_symbol_addr(
        zeDlHandle.get(), "zeCommandListCreate", lib_name);
    if (libze_ops.zeCommandListCreate == nullptr) {
        fprintf(stderr, "zeCommandListCreate symbol not found in %s\n",
                lib_name);
        return -1;
    }
    *(void **)&libze_ops.zeCommandListDestroy = utils_get_symbol_addr(
        zeDlHandle.get(), "zeCommandListDestroy", lib_name);
    if (libze_ops.zeCommandListDestroy == nullptr) {
        fprintf(stderr, "zeCommandListDestroy symbol not found in %s\n",
                lib_name);
        return -1;
    }
    *(void **)&libze_ops.zeCommandListClose =
        utils_get_symbol_addr(zeDlHandle.get(), "zeCommandListClose", lib_name);
    if (libze_ops.zeCommandListClose == nullptr) {
        fprintf(stderr, "zeCommandListClose symbol not found in %s\n",
                lib_name);
        return -1;
    }
    *(void **)&libze_ops.zeCommandListAppendMemoryCopy = utils_get_symbol_addr(
        zeDlHandle.get(), "zeCommandListAppendMemoryCopy", lib_name);
    if (libze_ops.zeCommandListAppendMemoryCopy == nullptr) {
        fprintf(stderr,
                "zeCommandListAppendMemoryCopy symbol not found in %s\n",
                lib_name);
        return -1;
    }
    *(void **)&libze_ops.zeCommandListAppendMemoryFill = utils_get_symbol_addr(
        zeDlHandle.get(), "zeCommandListAppendMemoryFill", lib_name);
    if (libze_ops.zeCommandListAppendMemoryFill == nullptr) {
        fprintf(stderr,
                "zeCommandListAppendMemoryFill symbol not found in %s\n",
                lib_name);
        return -1;
    }
    *(void **)&libze_ops.zeMemGetAllocProperties = utils_get_symbol_addr(
        zeDlHandle.get(), "zeMemGetAllocProperties", lib_name);
    if (libze_ops.zeMemGetAllocProperties == nullptr) {
        fprintf(stderr, "zeMemGetAllocProperties symbol not found in %s\n",
                lib_name);
        return -1;
    }
    *(void **)&libze_ops.zeMemAllocDevice =
        utils_get_symbol_addr(zeDlHandle.get(), "zeMemAllocDevice", lib_name);
    if (libze_ops.zeMemAllocDevice == nullptr) {
        fprintf(stderr, "zeMemAllocDevice symbol not found in %s\n", lib_name);
        return -1;
    }
    *(void **)&libze_ops.zeMemFree =
        utils_get_symbol_addr(zeDlHandle.get(), "zeMemFree", lib_name);
    if (libze_ops.zeMemFree == nullptr) {
        fprintf(stderr, "zeMemFree symbol not found in %s\n", lib_name);
        return -1;
    }

    return 0;
}

#else  // USE_DLOPEN
int InitLevelZeroOps() {
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

    return 0;
}
#endif // USE_DLOPEN

static int init_level_zero_lib(void) {
    ze_init_flag_t flags = ZE_INIT_FLAG_GPU_ONLY;
    ze_result_t result = libze_ops.zeInit(flags);
    if (result != ZE_RESULT_SUCCESS) {
        return -1;
    }
    return 0;
}

int get_drivers(uint32_t *drivers_num_, ze_driver_handle_t **drivers_) {
    int ret = 0;
    ze_result_t ze_result;
    ze_driver_handle_t *drivers = NULL;
    uint32_t drivers_num = 0;

    ze_result = libze_ops.zeDriverGet(&drivers_num, NULL);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeDriverGet() failed!\n");
        ret = -1;
        goto fn_fail;
    }
    if (drivers_num == 0) {
        goto fn_exit;
    }

    drivers =
        (ze_driver_handle_t *)malloc(drivers_num * sizeof(ze_driver_handle_t));
    if (!drivers) {
        ret = -1;
        goto fn_fail;
    }

    ze_result = libze_ops.zeDriverGet(&drivers_num, drivers);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeDriverGet() failed!\n");
        ret = -1;
        goto fn_fail;
    }

fn_exit:
    *drivers_num_ = drivers_num;
    *drivers_ = drivers;
    return ret;

fn_fail:
    *drivers_num_ = 0;
    if (drivers) {
        free(drivers);
        *drivers_ = NULL;
    }
    return ret;
}

int get_devices(ze_driver_handle_t driver, uint32_t *devices_num_,
                ze_device_handle_t **devices_) {
    ze_result_t ze_result;
    int ret = 0;
    uint32_t devices_num = 0;
    ze_device_handle_t *devices = NULL;

    ze_result = libze_ops.zeDeviceGet(driver, &devices_num, NULL);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeDeviceGet() failed!\n");
        ret = -1;
        goto fn_fail;
    }
    if (devices_num == 0) {
        goto fn_exit;
    }

    devices =
        (ze_device_handle_t *)malloc(devices_num * sizeof(ze_device_handle_t));
    if (!devices) {
        ret = -1;
        goto fn_fail;
    }

    ze_result = libze_ops.zeDeviceGet(driver, &devices_num, devices);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeDeviceGet() failed!\n");
        ret = -1;
        goto fn_fail;
    }

fn_exit:
    *devices_num_ = devices_num;
    *devices_ = devices;
    return ret;

fn_fail:
    devices_num = 0;
    if (devices) {
        free(devices);
        devices = NULL;
    }
    return ret;
}

int find_driver_with_gpu(uint32_t *driver_idx, ze_driver_handle_t *driver_) {
    int ret = 0;
    ze_result_t ze_result;
    uint32_t drivers_num = 0;
    ze_device_handle_t *devices = NULL;
    ze_driver_handle_t *drivers = NULL;
    ze_driver_handle_t driver_with_gpus = NULL;

    ret = get_drivers(&drivers_num, &drivers);
    if (ret) {
        goto fn_fail;
    }

    /* Find a driver with GPU */
    for (uint32_t i = 0; i < drivers_num; ++i) {
        uint32_t devices_num = 0;
        ze_driver_handle_t driver = drivers[i];

        ret = get_devices(driver, &devices_num, &devices);
        if (ret) {
            goto fn_fail;
        }

        for (uint32_t d = 0; d < devices_num; ++d) {
            ze_device_handle_t device = devices[d];
            ze_device_properties_t device_properties;
            device_properties.stype = ZE_STRUCTURE_TYPE_DEVICE_PROPERTIES;
            device_properties.pNext = NULL;

            ze_result =
                libze_ops.zeDeviceGetProperties(device, &device_properties);
            if (ze_result != ZE_RESULT_SUCCESS) {
                fprintf(stderr, "zeDeviceGetProperties() failed!\n");
                ret = -1;
                goto fn_fail;
            }

            if (device_properties.type == ZE_DEVICE_TYPE_GPU) {
                driver_with_gpus = driver;
                *driver_idx = i;
                break;
            }
        }

        if (devices) {
            free(devices);
            devices = NULL;
        }

        if (driver_with_gpus != NULL) {
            goto fn_exit;
        }
    }

fn_fail:
    if (devices) {
        free(devices);
    }

fn_exit:
    *driver_ = driver_with_gpus;
    if (drivers) {
        free(drivers);
    }
    return ret;
}

int find_gpu_device(ze_driver_handle_t driver, ze_device_handle_t *device_) {
    int ret = -1;
    uint32_t devices_num = 0;
    ze_device_handle_t *devices = NULL;
    ze_device_handle_t device;

    ret = get_devices(driver, &devices_num, &devices);
    if (ret) {
        return ret;
    }

    for (uint32_t d = 0; d < devices_num; ++d) {
        device = devices[d];
        ze_device_properties_t device_properties;
        device_properties.stype = ZE_STRUCTURE_TYPE_DEVICE_PROPERTIES;
        device_properties.pNext = NULL;

        ze_result_t ze_result =
            libze_ops.zeDeviceGetProperties(device, &device_properties);
        if (ze_result != ZE_RESULT_SUCCESS) {
            fprintf(stderr, "zeDeviceGetProperties() failed!\n");
            ret = -1;
            break;
        }

        if (device_properties.type == ZE_DEVICE_TYPE_GPU) {
            *device_ = device;
            ret = 0;
            break;
        }
    }

    if (devices) {
        free(devices);
    }
    return ret;
}

int level_zero_fill(ze_context_handle_t context, ze_device_handle_t device,
                    void *ptr, size_t size, const void *pattern,
                    size_t pattern_size) {
    int ret = 0;

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
        context, device, &commandQueueDesc, &hCommandQueue);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandQueueCreate() failed!\n");
        return -1;
    }

    ze_command_list_handle_t hCommandList;
    ze_result = libze_ops.zeCommandListCreate(context, device, &commandListDesc,
                                              &hCommandList);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandListCreate() failed!\n");
        ret = -1;
        goto err_queue_destroy;
    }

    // fill memory with a pattern
    ze_result = libze_ops.zeCommandListAppendMemoryFill(
        hCommandList, ptr, pattern, pattern_size, size, NULL, 0, NULL);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandListAppendMemoryFill() failed!\n");
        ret = -1;
        goto err_list_destroy;
    }

    // close and execute the command list
    ze_result = libze_ops.zeCommandListClose(hCommandList);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandListClose() failed!\n");
        ret = -1;
        goto err_list_destroy;
    }

    ze_result = libze_ops.zeCommandQueueExecuteCommandLists(
        hCommandQueue, 1, &hCommandList, NULL);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandQueueExecuteCommandLists() failed!\n");
        ret = -1;
        goto err_list_destroy;
    }

    // sync
    ze_result = libze_ops.zeCommandQueueSynchronize(hCommandQueue, UINT64_MAX);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandQueueSynchronize() failed!\n");
        ret = -1;
        goto err_list_destroy;
    }

    // cleanup
err_list_destroy:
    ze_result = libze_ops.zeCommandListDestroy(hCommandList);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandListDestroy() failed!\n");
        ret = -1;
    }

err_queue_destroy:
    ze_result = libze_ops.zeCommandQueueDestroy(hCommandQueue);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandQueueDestroy() failed!\n");
        ret = -1;
    }

    return ret;
}

int level_zero_copy(ze_context_handle_t context, ze_device_handle_t device,
                    void *dst_ptr, const void *src_ptr, size_t size) {
    int ret = 0;
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
        context, device, &commandQueueDesc, &hCommandQueue);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandQueueCreate() failed!\n");
        return -1;
    }

    ze_command_list_handle_t hCommandList;
    ze_result = libze_ops.zeCommandListCreate(context, device, &commandListDesc,
                                              &hCommandList);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandListCreate() failed!\n");
        ret = -1;
        goto err_queue_destroy;
    }

    // copy from device memory to host memory
    ze_result = libze_ops.zeCommandListAppendMemoryCopy(
        hCommandList, dst_ptr, src_ptr, size, NULL, 0, NULL);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandListAppendMemoryCopy() failed!\n");
        ret = -1;
        goto err_list_destroy;
    }

    // close and execute the command list
    ze_result = libze_ops.zeCommandListClose(hCommandList);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandListClose() failed!\n");
        ret = -1;
        goto err_list_destroy;
    }

    ze_result = libze_ops.zeCommandQueueExecuteCommandLists(
        hCommandQueue, 1, &hCommandList, NULL);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandQueueExecuteCommandLists() failed!\n");
        ret = -1;
        goto err_list_destroy;
    }

    ze_result = libze_ops.zeCommandQueueSynchronize(hCommandQueue, UINT64_MAX);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandQueueSynchronize() failed!\n");
        ret = -1;
        goto err_list_destroy;
    }

    // cleanup
err_list_destroy:
    ze_result = libze_ops.zeCommandListDestroy(hCommandList);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandListDestroy() failed!\n");
        ret = -1;
    }

err_queue_destroy:
    ze_result = libze_ops.zeCommandQueueDestroy(hCommandQueue);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandQueueDestroy() failed!\n");
        ret = -1;
    }

    return ret;
}

int create_context(ze_driver_handle_t driver, ze_context_handle_t *context) {
    ze_result_t ze_result;
    ze_context_desc_t ctxtDesc;
    ctxtDesc.stype = ZE_STRUCTURE_TYPE_CONTEXT_DESC;
    ctxtDesc.pNext = NULL;
    ctxtDesc.flags = 0;

    ze_result = libze_ops.zeContextCreate(driver, &ctxtDesc, context);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeContextCreate() failed!\n");
        return -1;
    }

    return 0;
}

int destroy_context(ze_context_handle_t context) {
    ze_result_t ze_result;
    ze_result = libze_ops.zeContextDestroy(context);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeContextDestroy() failed!\n");
        return -1;
    }

    return 0;
}

ze_memory_type_t get_mem_type(ze_context_handle_t context, void *ptr) {
    ze_device_handle_t device = NULL;
    ze_memory_allocation_properties_t alloc_props;
    alloc_props.stype = ZE_STRUCTURE_TYPE_MEMORY_ALLOCATION_PROPERTIES;
    alloc_props.pNext = NULL;
    alloc_props.type = ZE_MEMORY_TYPE_UNKNOWN;
    alloc_props.id = 0;
    alloc_props.pageSize = 0;

    libze_ops.zeMemGetAllocProperties(context, ptr, &alloc_props, &device);
    return alloc_props.type;
}

UTIL_ONCE_FLAG level_zero_init_flag;
int InitResult;
void init_level_zero_once() {
    InitResult = InitLevelZeroOps();
    if (InitResult != 0) {
        return;
    }
    InitResult = init_level_zero_lib();
}

int init_level_zero() {
    utils_init_once(&level_zero_init_flag, init_level_zero_once);

    return InitResult;
}

level_zero_memory_provider_params_t
create_level_zero_prov_params(umf_usm_memory_type_t memory_type) {
    level_zero_memory_provider_params_t params = {
        NULL, NULL, UMF_MEMORY_TYPE_UNKNOWN, NULL, 0};
    uint32_t driver_idx = 0;
    ze_driver_handle_t hDriver;
    ze_device_handle_t hDevice;
    ze_context_handle_t hContext;
    int ret = -1;

    ret = init_level_zero();
    if (ret != 0) {
        // Return empty params. Test will be skipped.
        return params;
    }

    ret = find_driver_with_gpu(&driver_idx, &hDriver);
    if (ret != 0 || hDriver == NULL) {
        // Return empty params. Test will be skipped.
        return params;
    }

    ret = find_gpu_device(hDriver, &hDevice);
    if (ret != 0 || hDevice == NULL) {
        // Return empty params. Test will be skipped.
        return params;
    }

    ret = create_context(hDriver, &hContext);
    if (ret != 0) {
        // Return empty params. Test will be skipped.
        return params;
    }

    params.level_zero_context_handle = hContext;

    if (memory_type == UMF_MEMORY_TYPE_HOST) {
        params.level_zero_device_handle = NULL;
    } else {
        params.level_zero_device_handle = hDevice;
    }

    params.memory_type = memory_type;

    return params;
}