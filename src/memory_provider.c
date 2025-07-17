/*
 *
 * Copyright (C) 2023-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <umf/base.h>
#include <umf/memory_provider.h>

#include "base_alloc.h"
#include "base_alloc_global.h"
#include "ctl/ctl_internal.h"
#include "libumf.h"
#include "memory_provider_internal.h"
#include "utils_assert.h"
#include "utils_name.h"

static umf_result_t CTL_SUBTREE_HANDLER(CTL_NONAME, by_handle)(
    void *ctx, umf_ctl_query_source_t source, void *arg, size_t size,
    umf_ctl_index_utlist_t *indexes, const char *extra_name,
    umf_ctl_query_type_t queryType, va_list args) {
    (void)indexes, (void)source, (void)ctx;

    umf_memory_provider_handle_t hProvider =
        *(umf_memory_provider_handle_t *)indexes->arg;
    hProvider->ops.ext_ctl(hProvider->provider_priv, /*unused*/ 0, extra_name,
                           arg, size, queryType, args);

    return UMF_RESULT_SUCCESS;
}

static umf_ctl_node_t CTL_NODE(by_handle)[] = {
    CTL_LEAF_SUBTREE(CTL_NONAME, by_handle),
    CTL_NODE_END,
};

static const struct ctl_argument CTL_ARG(by_handle) = CTL_ARG_PTR;

umf_ctl_node_t CTL_NODE(provider)[] = {CTL_CHILD_WITH_ARG(by_handle),
                                       CTL_NODE_END};

static umf_result_t umfDefaultPurgeLazy(void *provider, void *ptr,
                                        size_t size) {
    (void)provider;
    (void)ptr;
    (void)size;
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

static umf_result_t umfDefaultPurgeForce(void *provider, void *ptr,
                                         size_t size) {
    (void)provider;
    (void)ptr;
    (void)size;
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

static umf_result_t umfDefaultAllocationSplit(void *provider, void *ptr,
                                              size_t totalSize,
                                              size_t firstSize) {
    (void)provider;
    (void)ptr;
    (void)totalSize;
    (void)firstSize;
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

static umf_result_t umfDefaultAllocationMerge(void *provider, void *lowPtr,
                                              void *highPtr, size_t totalSize) {
    (void)provider;
    (void)lowPtr;
    (void)highPtr;
    (void)totalSize;
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

static umf_result_t umfDefaultGetIPCHandleSize(void *provider, size_t *size) {
    (void)provider;
    (void)size;
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

static umf_result_t umfDefaultGetIPCHandle(void *provider, const void *ptr,
                                           size_t size, void *providerIpcData) {
    (void)provider;
    (void)ptr;
    (void)size;
    (void)providerIpcData;
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

static umf_result_t umfDefaultPutIPCHandle(void *provider,
                                           void *providerIpcData) {
    (void)provider;
    (void)providerIpcData;
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

static umf_result_t umfDefaultOpenIPCHandle(void *provider,
                                            void *providerIpcData, void **ptr) {
    (void)provider;
    (void)providerIpcData;
    (void)ptr;
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

static umf_result_t umfDefaultCloseIPCHandle(void *provider, void *ptr,
                                             size_t size) {
    (void)provider;
    (void)ptr;
    (void)size;
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

static umf_result_t
umfDefaultCtlHandle(void *provider, umf_ctl_query_source_t operationType,
                    const char *name, void *arg, size_t size,
                    umf_ctl_query_type_t queryType, va_list args) {
    (void)provider;
    (void)operationType;
    (void)name;
    (void)arg;
    (void)size;
    (void)queryType;
    (void)args;
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

static umf_result_t
umfDefaultGetAllocationProperties(void *provider, const void *ptr,
                                  umf_memory_property_id_t propertyId,
                                  void *propertyValue) {
    (void)provider;
    (void)ptr;
    (void)propertyId;
    (void)propertyValue;
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

static umf_result_t umfDefaultGetAllocationPropertiesSize(
    void *provider, umf_memory_property_id_t propertyId, size_t *size) {
    (void)provider;
    (void)propertyId;
    (void)size;
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

void assignOpsExtDefaults(umf_memory_provider_ops_t *ops) {
    if (!ops->ext_purge_lazy) {
        ops->ext_purge_lazy = umfDefaultPurgeLazy;
    }

    if (!ops->ext_purge_force) {
        ops->ext_purge_force = umfDefaultPurgeForce;
    }

    if (!ops->ext_allocation_split) {
        ops->ext_allocation_split = umfDefaultAllocationSplit;
    }

    if (!ops->ext_allocation_merge) {
        ops->ext_allocation_merge = umfDefaultAllocationMerge;
    }

    if (!ops->ext_ctl) {
        ops->ext_ctl = umfDefaultCtlHandle;
    }

    if (!ops->ext_get_allocation_properties) {
        ops->ext_get_allocation_properties = umfDefaultGetAllocationProperties;
    }

    if (!ops->ext_get_allocation_properties_size) {
        ops->ext_get_allocation_properties_size =
            umfDefaultGetAllocationPropertiesSize;
    }
}

void assignOpsIpcDefaults(umf_memory_provider_ops_t *ops) {
    if (!ops->ext_get_ipc_handle_size) {
        ops->ext_get_ipc_handle_size = umfDefaultGetIPCHandleSize;
    }

    if (!ops->ext_get_ipc_handle) {
        ops->ext_get_ipc_handle = umfDefaultGetIPCHandle;
    }

    if (!ops->ext_put_ipc_handle) {
        ops->ext_put_ipc_handle = umfDefaultPutIPCHandle;
    }

    if (!ops->ext_open_ipc_handle) {
        ops->ext_open_ipc_handle = umfDefaultOpenIPCHandle;
    }

    if (!ops->ext_close_ipc_handle) {
        ops->ext_close_ipc_handle = umfDefaultCloseIPCHandle;
    }
}

#define CHECK_OP(ops, fn)                                                      \
    if (!(ops)->fn) {                                                          \
        LOG_ERR("missing function pointer: %s\n", #fn);                        \
        return false;                                                          \
    }

static bool validateOps(const umf_memory_provider_ops_t *ops) {
    // Validate mandatory operations one by one
    CHECK_OP(ops, alloc);
    CHECK_OP(ops, free);
    CHECK_OP(ops, get_recommended_page_size);
    CHECK_OP(ops, get_min_page_size);
    CHECK_OP(ops, initialize);
    CHECK_OP(ops, finalize);
    CHECK_OP(ops, get_last_native_error);
    CHECK_OP(ops, get_name);

    if ((ops->ext_allocation_split == NULL) !=
        (ops->ext_allocation_merge == NULL)) {
        LOG_ERR("ext_allocation_split and ext_allocation_merge must be "
                "both set or both NULL\n");
        return false;
    }

    bool ipcAllSet = ops->ext_get_ipc_handle_size && ops->ext_get_ipc_handle &&
                     ops->ext_put_ipc_handle && ops->ext_open_ipc_handle &&
                     ops->ext_close_ipc_handle;
    bool ipcAllNull = !ops->ext_get_ipc_handle_size &&
                      !ops->ext_get_ipc_handle && !ops->ext_put_ipc_handle &&
                      !ops->ext_open_ipc_handle && !ops->ext_close_ipc_handle;
    if (!ipcAllSet && !ipcAllNull) {
        LOG_ERR("IPC function pointers must be either all set or all "
                "NULL\n");
        return false;
    }

    if ((ops->ext_get_allocation_properties == NULL) !=
        (ops->ext_get_allocation_properties_size == NULL)) {
        LOG_ERR("ext_get_allocation_properties and "
                "ext_get_allocation_properties_size must be "
                "both set or both NULL\n");
        return false;
    }

    return true;
}

umf_result_t umfMemoryProviderCreate(const umf_memory_provider_ops_t *ops,
                                     const void *params,
                                     umf_memory_provider_handle_t *hProvider) {
    libumfInit();
    if (!ops || !hProvider) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_memory_provider_ops_t compatible_ops;
    if (ops->version != UMF_PROVIDER_OPS_VERSION_CURRENT) {
        LOG_WARN("Memory Provider ops version \"%d\" is different than the "
                 "current version \"%d\"",
                 ops->version, UMF_PROVIDER_OPS_VERSION_CURRENT);

        // Create a new ops compatible structure with the current version
        memset(&compatible_ops, 0, sizeof(compatible_ops));

        if (UMF_MINOR_VERSION(ops->version) == 0) {
            LOG_INFO("Detected 1.0 version of Memory Provider ops, "
                     "upgrading to current version");
            memcpy(&compatible_ops, ops,
                   offsetof(umf_memory_provider_ops_t,
                            ext_get_allocation_properties));
        } else {
            LOG_ERR("Unsupported Memory Provider ops version: %d",
                    ops->version);
            return UMF_RESULT_ERROR_NOT_SUPPORTED;
        }

        ops = &compatible_ops;
    }

    if (!validateOps(ops)) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_memory_provider_handle_t provider =
        umf_ba_global_alloc(sizeof(umf_memory_provider_t));
    if (!provider) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    provider->ops = *ops;

    assignOpsExtDefaults(&(provider->ops));
    assignOpsIpcDefaults(&(provider->ops));

    void *provider_priv;
    umf_result_t ret = ops->initialize(params, &provider_priv);
    if (ret != UMF_RESULT_SUCCESS) {
        umf_ba_global_free(provider);
        return ret;
    }

    provider->provider_priv = provider_priv;

    *hProvider = provider;

    const char *provider_name = NULL;
    if (provider->ops.get_name(provider->provider_priv, &provider_name) ==
            UMF_RESULT_SUCCESS &&
        provider_name) {
        utils_warn_invalid_name("Memory provider", provider_name);
    }

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfMemoryProviderDestroy(umf_memory_provider_handle_t hProvider) {
    if (umf_ba_global_is_destroyed()) {
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    if (!hProvider) {
        return UMF_RESULT_SUCCESS;
    }

    umf_result_t ret = hProvider->ops.finalize(hProvider->provider_priv);
    umf_ba_global_free(hProvider);
    return ret;
}

static void
checkErrorAndSetLastProvider(umf_result_t result,
                             umf_memory_provider_handle_t hProvider) {
    if (result != UMF_RESULT_SUCCESS) {
        *umfGetLastFailedMemoryProviderPtr() = hProvider;
    }
}

umf_result_t umfMemoryProviderAlloc(umf_memory_provider_handle_t hProvider,
                                    size_t size, size_t alignment, void **ptr) {
    UMF_CHECK((hProvider != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((ptr != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umf_result_t res =
        hProvider->ops.alloc(hProvider->provider_priv, size, alignment, ptr);

    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

umf_result_t umfMemoryProviderFree(umf_memory_provider_handle_t hProvider,
                                   void *ptr, size_t size) {
    UMF_CHECK((hProvider != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umf_result_t res = hProvider->ops.free(hProvider->provider_priv, ptr, size);

    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

umf_result_t
umfMemoryProviderGetLastNativeError(umf_memory_provider_handle_t hProvider,
                                    const char **ppMessage, int32_t *pError) {
    UMF_CHECK((hProvider != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((ppMessage != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((pError != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);

    return hProvider->ops.get_last_native_error(hProvider->provider_priv,
                                                ppMessage, pError);
}

void *umfMemoryProviderGetPriv(umf_memory_provider_handle_t hProvider) {
    UMF_CHECK((hProvider != NULL), NULL);

    return hProvider->provider_priv;
}

umf_result_t
umfMemoryProviderGetRecommendedPageSize(umf_memory_provider_handle_t hProvider,
                                        size_t size, size_t *pageSize) {
    UMF_CHECK((hProvider != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((pageSize != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umf_result_t res = hProvider->ops.get_recommended_page_size(
        hProvider->provider_priv, size, pageSize);

    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

umf_result_t
umfMemoryProviderGetMinPageSize(umf_memory_provider_handle_t hProvider,
                                const void *ptr, size_t *pageSize) {
    UMF_CHECK((hProvider != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((pageSize != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umf_result_t res = hProvider->ops.get_min_page_size(
        hProvider->provider_priv, ptr, pageSize);

    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

umf_result_t umfMemoryProviderGetName(umf_memory_provider_handle_t hProvider,
                                      const char **name) {
    UMF_CHECK((hProvider != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((name != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umf_result_t res = hProvider->ops.get_name(hProvider->provider_priv, name);

    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

umf_result_t umfMemoryProviderPurgeLazy(umf_memory_provider_handle_t hProvider,
                                        void *ptr, size_t size) {
    UMF_CHECK((hProvider != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((ptr != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ASSERT(hProvider->ops.ext_purge_lazy);
    umf_result_t res =
        hProvider->ops.ext_purge_lazy(hProvider->provider_priv, ptr, size);

    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

umf_result_t umfMemoryProviderPurgeForce(umf_memory_provider_handle_t hProvider,
                                         void *ptr, size_t size) {
    UMF_CHECK((hProvider != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((ptr != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ASSERT(hProvider->ops.ext_purge_force);
    umf_result_t res =
        hProvider->ops.ext_purge_force(hProvider->provider_priv, ptr, size);

    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

umf_result_t
umfGetLastFailedMemoryProvider(umf_memory_provider_handle_t *provider) {
    UMF_CHECK((provider != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);

    *provider = *umfGetLastFailedMemoryProviderPtr();
    return UMF_RESULT_SUCCESS;
}

umf_result_t
umfMemoryProviderAllocationSplit(umf_memory_provider_handle_t hProvider,
                                 void *ptr, size_t totalSize,
                                 size_t firstSize) {
    UMF_CHECK((hProvider != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((ptr != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((firstSize != 0 && totalSize != 0),
              UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((firstSize < totalSize), UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ASSERT(hProvider->ops.ext_allocation_split);
    umf_result_t res = hProvider->ops.ext_allocation_split(
        hProvider->provider_priv, ptr, totalSize, firstSize);

    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

umf_result_t
umfMemoryProviderAllocationMerge(umf_memory_provider_handle_t hProvider,
                                 void *lowPtr, void *highPtr,
                                 size_t totalSize) {
    UMF_CHECK((hProvider != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((lowPtr && highPtr), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((totalSize != 0), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK(((uintptr_t)lowPtr < (uintptr_t)highPtr),
              UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK(((uintptr_t)highPtr - (uintptr_t)lowPtr < totalSize),
              UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ASSERT(hProvider->ops.ext_allocation_merge);
    umf_result_t res = hProvider->ops.ext_allocation_merge(
        hProvider->provider_priv, lowPtr, highPtr, totalSize);

    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

umf_result_t
umfMemoryProviderGetIPCHandleSize(umf_memory_provider_handle_t hProvider,
                                  size_t *size) {
    UMF_CHECK((hProvider != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((size != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ASSERT(hProvider->ops.ext_get_ipc_handle_size);
    umf_result_t res =
        hProvider->ops.ext_get_ipc_handle_size(hProvider->provider_priv, size);

    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

umf_result_t
umfMemoryProviderGetIPCHandle(umf_memory_provider_handle_t hProvider,
                              const void *ptr, size_t size,
                              void *providerIpcData) {
    UMF_CHECK((hProvider != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((ptr != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((size != 0), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((providerIpcData != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ASSERT(hProvider->ops.ext_get_ipc_handle);
    umf_result_t res = hProvider->ops.ext_get_ipc_handle(
        hProvider->provider_priv, ptr, size, providerIpcData);

    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

umf_result_t
umfMemoryProviderPutIPCHandle(umf_memory_provider_handle_t hProvider,
                              void *providerIpcData) {
    UMF_CHECK((hProvider != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((providerIpcData != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ASSERT(hProvider->ops.ext_put_ipc_handle);
    umf_result_t res = hProvider->ops.ext_put_ipc_handle(
        hProvider->provider_priv, providerIpcData);

    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

umf_result_t
umfMemoryProviderOpenIPCHandle(umf_memory_provider_handle_t hProvider,
                               void *providerIpcData, void **ptr) {
    UMF_CHECK((hProvider != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((providerIpcData != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((ptr != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ASSERT(hProvider->ops.ext_open_ipc_handle);
    umf_result_t res = hProvider->ops.ext_open_ipc_handle(
        hProvider->provider_priv, providerIpcData, ptr);

    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

umf_result_t
umfMemoryProviderCloseIPCHandle(umf_memory_provider_handle_t hProvider,
                                void *ptr, size_t size) {
    UMF_CHECK((hProvider != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((ptr != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((size != 0), UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ASSERT(hProvider->ops.ext_close_ipc_handle);
    umf_result_t res = hProvider->ops.ext_close_ipc_handle(
        hProvider->provider_priv, ptr, size);

    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

umf_result_t umfMemoryProviderGetAllocationProperties(
    umf_memory_provider_handle_t hProvider, const void *ptr,
    umf_memory_property_id_t propertyId, void *property_value) {

    UMF_CHECK((hProvider != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((property_value != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((propertyId != UMF_MEMORY_PROPERTY_INVALID),
              UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // NOTE: we do not check if the propertyId is below
    // UMF_MEMORY_PROPERTY_MAX_RESERVED value, as the user could use a custom
    // property ID that is above the reserved range

    umf_result_t res = hProvider->ops.ext_get_allocation_properties(
        hProvider->provider_priv, ptr, propertyId, property_value);

    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

umf_result_t umfMemoryProviderGetAllocationPropertiesSize(
    umf_memory_provider_handle_t hProvider, umf_memory_property_id_t propertyId,
    size_t *size) {

    UMF_CHECK((hProvider != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((size != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((propertyId != UMF_MEMORY_PROPERTY_INVALID),
              UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // NOTE: we do not check if the propertyId is below
    // UMF_MEMORY_PROPERTY_MAX_RESERVED value, as the user could use a custom
    // property ID that is above the reserved range

    umf_result_t res = hProvider->ops.ext_get_allocation_properties_size(
        hProvider->provider_priv, propertyId, size);

    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}
