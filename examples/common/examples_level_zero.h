/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_EXAMPLE_UTILS_LEVEL_ZERO_H
#define UMF_EXAMPLE_UTILS_LEVEL_ZERO_H

#include <stdio.h>
#include <stdlib.h>

// To use the Level Zero API, the Level Zero SDK has to be installed
// on the system
#ifdef _WIN32
#include <ze_api.h>
#else
#include <level_zero/ze_api.h>
#endif

static int init_level_zero(void) {
    ze_init_flag_t flags = ZE_INIT_FLAG_GPU_ONLY;
    ze_result_t result = zeInit(flags);
    if (result != ZE_RESULT_SUCCESS) {
        return -1;
    }
    return 0;
}

static inline int get_drivers(uint32_t *drivers_num_,
                              ze_driver_handle_t **drivers_) {
    int ret = 0;
    ze_result_t ze_result;
    ze_driver_handle_t *drivers = NULL;
    uint32_t drivers_num = 0;

    ze_result = zeDriverGet(&drivers_num, NULL);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeDriverGet() failed!\n");
        ret = -1;
        goto fn_fail;
    }
    if (drivers_num == 0) {
        goto fn_exit;
    }

    drivers = malloc(drivers_num * sizeof(ze_driver_handle_t));
    if (!drivers) {
        ret = -1;
        goto fn_fail;
    }

    ze_result = zeDriverGet(&drivers_num, drivers);
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

static inline int get_devices(ze_driver_handle_t driver, uint32_t *devices_num_,
                              ze_device_handle_t **devices_) {
    ze_result_t ze_result;
    int ret = 0;
    uint32_t devices_num = 0;
    ze_device_handle_t *devices = NULL;

    ze_result = zeDeviceGet(driver, &devices_num, NULL);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeDeviceGet() failed!\n");
        ret = -1;
        goto fn_fail;
    }
    if (devices_num == 0) {
        goto fn_exit;
    }

    devices = malloc(devices_num * sizeof(ze_device_handle_t));
    if (!devices) {
        ret = -1;
        goto fn_fail;
    }

    ze_result = zeDeviceGet(driver, &devices_num, devices);
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

static inline int find_driver_with_gpu(uint32_t *driver_idx,
                                       ze_driver_handle_t *driver_) {
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
            ze_device_properties_t device_properties = {
                .stype = ZE_STRUCTURE_TYPE_DEVICE_PROPERTIES, .pNext = NULL};

            ze_result = zeDeviceGetProperties(device, &device_properties);
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

static inline int find_gpu_device(ze_driver_handle_t driver,
                                  ze_device_handle_t *device_) {
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
        ze_device_properties_t device_properties = {
            .stype = ZE_STRUCTURE_TYPE_DEVICE_PROPERTIES, .pNext = NULL};

        ze_result_t ze_result =
            zeDeviceGetProperties(device, &device_properties);
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
    ze_result_t ze_result = zeCommandQueueCreate(
        context, device, &commandQueueDesc, &hCommandQueue);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandQueueCreate() failed!\n");
        return -1;
    }

    ze_command_list_handle_t hCommandList;
    ze_result =
        zeCommandListCreate(context, device, &commandListDesc, &hCommandList);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandListCreate() failed!\n");
        ret = -1;
        goto err_queue_destroy;
    }

    // fill memory with a pattern
    ze_result = zeCommandListAppendMemoryFill(
        hCommandList, ptr, pattern, pattern_size, size, NULL, 0, NULL);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandListAppendMemoryFill() failed!\n");
        ret = -1;
        goto err_list_destroy;
    }

    // close and execute the command list
    ze_result = zeCommandListClose(hCommandList);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandListClose() failed!\n");
        ret = -1;
        goto err_list_destroy;
    }

    ze_result = zeCommandQueueExecuteCommandLists(hCommandQueue, 1,
                                                  &hCommandList, NULL);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandQueueExecuteCommandLists() failed!\n");
        ret = -1;
        goto err_list_destroy;
    }

    // sync
    ze_result = zeCommandQueueSynchronize(hCommandQueue, UINT64_MAX);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandQueueSynchronize() failed!\n");
        ret = -1;
        goto err_list_destroy;
    }

    // cleanup
err_list_destroy:
    ze_result = zeCommandListDestroy(hCommandList);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandListDestroy() failed!\n");
        ret = -1;
    }

err_queue_destroy:
    ze_result = zeCommandQueueDestroy(hCommandQueue);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandQueueDestroy() failed!\n");
        ret = -1;
    }

    return ret;
}

int level_zero_copy(ze_context_handle_t context, ze_device_handle_t device,
                    void *dst_ptr, void *src_ptr, size_t size) {
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
    ze_result_t ze_result = zeCommandQueueCreate(
        context, device, &commandQueueDesc, &hCommandQueue);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandQueueCreate() failed!\n");
        return -1;
    }

    ze_command_list_handle_t hCommandList;
    ze_result =
        zeCommandListCreate(context, device, &commandListDesc, &hCommandList);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandListCreate() failed!\n");
        ret = -1;
        goto err_queue_destroy;
    }

    // copy from device memory to host memory
    ze_result = zeCommandListAppendMemoryCopy(hCommandList, dst_ptr, src_ptr,
                                              size, NULL, 0, NULL);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandListAppendMemoryCopy() failed!\n");
        ret = -1;
        goto err_list_destroy;
    }

    // close and execute the command list
    ze_result = zeCommandListClose(hCommandList);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandListClose() failed!\n");
        ret = -1;
        goto err_list_destroy;
    }

    ze_result = zeCommandQueueExecuteCommandLists(hCommandQueue, 1,
                                                  &hCommandList, NULL);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandQueueExecuteCommandLists() failed!\n");
        ret = -1;
        goto err_list_destroy;
    }

    ze_result = zeCommandQueueSynchronize(hCommandQueue, UINT64_MAX);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandQueueSynchronize() failed!\n");
        ret = -1;
        goto err_list_destroy;
    }

    // cleanup
err_list_destroy:
    ze_result = zeCommandListDestroy(hCommandList);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandListDestroy() failed!\n");
        ret = -1;
    }

err_queue_destroy:
    ze_result = zeCommandQueueDestroy(hCommandQueue);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeCommandQueueDestroy() failed!\n");
        ret = -1;
    }

    return ret;
}

int create_context(ze_driver_handle_t driver, ze_context_handle_t *context) {
    ze_result_t ze_result;
    ze_context_desc_t ctxtDesc = {
        .stype = ZE_STRUCTURE_TYPE_CONTEXT_DESC, .pNext = NULL, .flags = 0};

    ze_result = zeContextCreate(driver, &ctxtDesc, context);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeContextCreate() failed!\n");
        return -1;
    }

    return 0;
}

int destroy_context(ze_context_handle_t context) {
    ze_result_t ze_result;
    ze_result = zeContextDestroy(context);
    if (ze_result != ZE_RESULT_SUCCESS) {
        fprintf(stderr, "zeContextDestroy() failed!\n");
        return -1;
    }

    return 0;
}

#endif // UMF_EXAMPLE_UTILS_LEVEL_ZERO_H
