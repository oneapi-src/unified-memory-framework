/*
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <umf.h>
#include <umf/memory_provider.h>
#include <umf/memory_provider_ops.h>

#include "provider_deprecated.h"
#include "utils_log.h"

#if defined(_WIN32) || defined(UMF_NO_HWLOC)

umf_memory_provider_ops_t *umfFileMemoryProviderOps_0_10(void) {
    // not supported
    LOG_ERR("File memory provider is disabled!");
    return NULL;
}

#else // !defined(_WIN32) && !defined(UMF_NO_HWLOC)

// The ops structure for the File Memory Povider has been changed between
// UMF 0.10 and 0.11 (in 0.10 there was no "free()" method)

extern umf_memory_provider_ops_0_11_t UMF_FILE_MEMORY_PROVIDER_OPS_0_11;
static umf_memory_provider_ops_0_10_t UMF_FILE_MEMORY_PROVIDER_OPS_0_10;

#if !defined(__APPLE__)
// Set 0_10 version as the default one for dlsym()
asm(".symver "
    "umfFileMemoryProviderOps_0_10,umfFileMemoryProviderOps@@UMF_0.10");
#endif

umf_memory_provider_ops_0_10_t *umfFileMemoryProviderOps_0_10(void) {
    umf_memory_provider_ops_0_11_t ops = UMF_FILE_MEMORY_PROVIDER_OPS_0_11;
    umf_memory_provider_ops_0_10_t ops_0_10 = {
        .version = UMF_MAKE_VERSION(0, 10),
        .initialize = ops.initialize,
        .finalize = ops.finalize,
        .alloc = ops.alloc,
        .get_last_native_error = ops.get_last_native_error,
        .get_recommended_page_size = ops.get_recommended_page_size,
        .get_min_page_size = ops.get_min_page_size,
        .get_name = ops.get_name,
        .ext.purge_lazy = ops.ext.purge_lazy,
        .ext.purge_force = ops.ext.purge_force,
        .ext.allocation_merge = ops.ext.allocation_merge,
        .ext.allocation_split = ops.ext.allocation_split,
        .ipc.get_ipc_handle_size = ops.ipc.get_ipc_handle_size,
        .ipc.get_ipc_handle = ops.ipc.get_ipc_handle,
        .ipc.put_ipc_handle = ops.ipc.put_ipc_handle,
        .ipc.open_ipc_handle = ops.ipc.open_ipc_handle,
        .ipc.close_ipc_handle = ops.ipc.close_ipc_handle,
    };

    UMF_FILE_MEMORY_PROVIDER_OPS_0_10 = ops_0_10;
    return &UMF_FILE_MEMORY_PROVIDER_OPS_0_10;
}

#endif // !defined(_WIN32) && !defined(UMF_NO_HWLOC)
