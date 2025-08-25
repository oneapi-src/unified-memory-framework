// Copyright (C) 2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#ifndef UMF_TEST_ZE_LOOPBACK_H
#define UMF_TEST_ZE_LOOPBACK_H

#include "ze_api.h"

class LevelZero {
  public:
    virtual ~LevelZero() = default;

    virtual ze_result_t zeContextCreate(ze_driver_handle_t,
                                        const ze_context_desc_t *,
                                        ze_context_handle_t *) = 0;
    virtual ze_result_t zeDeviceGetProperties(ze_device_handle_t,
                                              ze_device_properties_t *) = 0;
    virtual ze_result_t zeMemAllocDevice(ze_context_handle_t,
                                         const ze_device_mem_alloc_desc_t *,
                                         size_t, size_t, ze_device_handle_t,
                                         void **) = 0;
    virtual ze_result_t
    zeMemGetAllocProperties(ze_context_handle_t, const void *,
                            ze_memory_allocation_properties_t *,
                            ze_device_handle_t *) = 0;
    virtual ze_result_t zeContextMakeMemoryResident(ze_context_handle_t,
                                                    ze_device_handle_t, void *,
                                                    size_t) = 0;
    virtual ze_result_t zeMemFree(ze_context_handle_t hContext, void *ptr) = 0;
};

#endif //UMF_TEST_ZE_LOOPBACK_H
