/*
 *
 * Copyright (C) 2023-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include <umf/base.h>
#include <umf/memory_pool.h>
#include <umf/memory_pool_ops.h>

#include "base_alloc_global.h"
#include "ctl/ctl_internal.h"
#include "libumf.h"
#include "memory_pool_internal.h"
#include "memory_provider_internal.h"
#include "provider_tracking.h"
#include "utils_assert.h"
#include "utils_concurrency.h"
#include "utils_log.h"

#define UMF_DEFAULT_SIZE 100
#define UMF_DEFAULT_LEN 100

utils_mutex_t ctl_mtx;
static UTIL_ONCE_FLAG mem_pool_ctl_initialized = UTIL_ONCE_FLAG_INIT;

char CTL_DEFAULT_ENTRIES[UMF_DEFAULT_SIZE][UMF_DEFAULT_LEN] = {0};
char CTL_DEFAULT_VALUES[UMF_DEFAULT_SIZE][UMF_DEFAULT_LEN] = {0};

static struct ctl umf_pool_ctl_root;

static void ctl_init(void);

static umf_result_t CTL_SUBTREE_HANDLER(CTL_NONAME, by_handle)(
    void *ctx, umf_ctl_query_source_t source, void *arg, size_t size,
    umf_ctl_index_utlist_t *indexes, const char *extra_name,
    umf_ctl_query_type_t queryType, va_list args) {
    (void)source, (void)ctx;

    umf_memory_pool_handle_t hPool = *(umf_memory_pool_handle_t *)indexes->arg;
    va_list args2;
    va_copy(args2, args);

    umf_result_t ret = ctl_query(&umf_pool_ctl_root, hPool, source, extra_name,
                                 queryType, arg, size, args2);
    va_end(args2);

    if (ret == UMF_RESULT_ERROR_INVALID_ARGUMENT) {
        // Node was not found in pool_ctl_root, try to query the specific pool
        ret = hPool->ops.ext_ctl(hPool->pool_priv, source, extra_name, arg,
                                 size, queryType, args);
    }

    return ret;
}

static umf_result_t CTL_SUBTREE_HANDLER(default)(
    void *ctx, umf_ctl_query_source_t source, void *arg, size_t size,
    umf_ctl_index_utlist_t *indexes, const char *extra_name,
    umf_ctl_query_type_t queryType, va_list args) {
    (void)indexes, (void)source, (void)ctx, (void)args;
    utils_init_once(&mem_pool_ctl_initialized, ctl_init);

    if (strstr(extra_name, "{}") != NULL) {
        // We might implement it in future - it requires store copy of va_list
        // in defaults entries array, which according to C standard is possible,
        // but quite insane.
        LOG_ERR("%s, default setting do not support wildcard parameters {}",
                extra_name);
        return UMF_RESULT_ERROR_NOT_SUPPORTED;
    }

    utils_mutex_lock(&ctl_mtx);

    if (queryType == CTL_QUERY_WRITE) {
        int i = 0;
        for (; i < UMF_DEFAULT_SIZE; i++) {
            if (CTL_DEFAULT_ENTRIES[i][0] == '\0' ||
                strcmp(CTL_DEFAULT_ENTRIES[i], extra_name) == 0) {
                strncpy(CTL_DEFAULT_ENTRIES[i], extra_name, UMF_DEFAULT_LEN);
                CTL_DEFAULT_ENTRIES[i][UMF_DEFAULT_LEN - 1] = '\0';
                strncpy(CTL_DEFAULT_VALUES[i], arg, UMF_DEFAULT_LEN);
                CTL_DEFAULT_VALUES[i][UMF_DEFAULT_LEN - 1] = '\0';
                break;
            }
        }
        if (UMF_DEFAULT_SIZE == i) {
            LOG_ERR("Default entries array is full");
            utils_mutex_unlock(&ctl_mtx);
            return UMF_RESULT_ERROR_OUT_OF_RESOURCES;
        }
    } else if (queryType == CTL_QUERY_READ) {
        int i = 0;
        for (; i < UMF_DEFAULT_SIZE; i++) {
            if (strcmp(CTL_DEFAULT_ENTRIES[i], extra_name) == 0) {
                strncpy(arg, CTL_DEFAULT_VALUES[i], size);
                break;
            }
        }
        if (UMF_DEFAULT_SIZE == i) {
            LOG_WARN("Wrong path name: %s", extra_name);
            utils_mutex_unlock(&ctl_mtx);
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
    }

    utils_mutex_unlock(&ctl_mtx);

    return UMF_RESULT_SUCCESS;
}

static umf_result_t
CTL_READ_HANDLER(alloc_count)(void *ctx, umf_ctl_query_source_t source,
                              void *arg, size_t size,
                              umf_ctl_index_utlist_t *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)size, (void)indexes;

    size_t *arg_out = arg;
    if (ctx == NULL || arg_out == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    assert(size == sizeof(size_t));

    umf_memory_pool_handle_t pool = (umf_memory_pool_handle_t)ctx;
    utils_atomic_load_acquire_size_t(&pool->stats.alloc_count, arg_out);
    return UMF_RESULT_SUCCESS;
}

static const umf_ctl_node_t CTL_NODE(stats)[] = {CTL_LEAF_RO(alloc_count),
                                                 CTL_NODE_END};

static umf_ctl_node_t CTL_NODE(by_handle)[] = {
    CTL_LEAF_SUBTREE(CTL_NONAME, by_handle),
    CTL_NODE_END,
};

static const struct ctl_argument CTL_ARG(by_handle) = CTL_ARG_PTR;

umf_ctl_node_t CTL_NODE(pool)[] = {CTL_CHILD_WITH_ARG(by_handle),
                                   CTL_LEAF_SUBTREE(default), CTL_NODE_END};

static void ctl_init(void) {
    utils_mutex_init(&ctl_mtx);
    CTL_REGISTER_MODULE(&umf_pool_ctl_root, stats);
}

static umf_result_t
umfDefaultCtlPoolHandle(void *hPool, umf_ctl_query_source_t operationType,
                        const char *name, void *arg, size_t size,
                        umf_ctl_query_type_t queryType, va_list args) {
    (void)hPool;
    (void)operationType;
    (void)name;
    (void)arg;
    (void)size;
    (void)queryType;
    (void)args;
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

// logical sum (OR) of all umf_pool_create_flags_t flags
static const umf_pool_create_flags_t UMF_POOL_CREATE_FLAG_ALL =
    UMF_POOL_CREATE_FLAG_OWN_PROVIDER | UMF_POOL_CREATE_FLAG_DISABLE_TRACKING;

// windows do not allow to use uninitialized va_list so this function help us to initialize it.
static umf_result_t default_ctl_helper(const umf_memory_pool_ops_t *ops,
                                       void *ctl, const char *name, void *arg,
                                       ...) {
    va_list empty_args;
    va_start(empty_args, arg);
    umf_result_t ret =
        ops->ext_ctl(ctl, CTL_QUERY_PROGRAMMATIC, name, arg, UMF_DEFAULT_LEN,
                     CTL_QUERY_WRITE, empty_args);
    va_end(empty_args);
    return ret;
}

static umf_result_t umfPoolCreateInternal(const umf_memory_pool_ops_t *ops,
                                          umf_memory_provider_handle_t provider,
                                          const void *params,
                                          umf_pool_create_flags_t flags,
                                          umf_memory_pool_handle_t *hPool) {
    if (!ops || !provider || !hPool) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    // validate flags
    if (flags & ~UMF_POOL_CREATE_FLAG_ALL) {
        LOG_ERR("Invalid flags: 0x%x", flags);
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_result_t ret = UMF_RESULT_SUCCESS;

    if (ops->version != UMF_POOL_OPS_VERSION_CURRENT) {
        LOG_WARN("Memory Pool ops version \"%d\" is different than the current "
                 "version \"%d\"",
                 ops->version, UMF_POOL_OPS_VERSION_CURRENT);
    }

    umf_memory_pool_handle_t pool =
        umf_ba_global_alloc(sizeof(umf_memory_pool_t));
    if (!pool) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    if (!(flags & UMF_POOL_CREATE_FLAG_DISABLE_TRACKING)) {
        // Wrap provider with memory tracking provider.
        ret = umfTrackingMemoryProviderCreate(provider, pool, &pool->provider);
        if (ret != UMF_RESULT_SUCCESS) {
            goto err_provider_create;
        }
    } else {
        pool->provider = provider;
    }

    utils_init_once(&mem_pool_ctl_initialized, ctl_init);

    pool->flags = flags;
    pool->ops = *ops;
    pool->tag = NULL;
    memset(&pool->stats, 0, sizeof(pool->stats));

    if (NULL == pool->ops.ext_ctl) {
        pool->ops.ext_ctl = umfDefaultCtlPoolHandle;
    }

    if (NULL == utils_mutex_init(&pool->lock)) {
        LOG_ERR("Failed to initialize mutex for pool");
        ret = UMF_RESULT_ERROR_UNKNOWN;
        goto err_lock_init;
    }

    ret = ops->initialize(pool->provider, params, &pool->pool_priv);
    if (ret != UMF_RESULT_SUCCESS) {
        goto err_pool_init;
    }

    // Set default property "name" to pool if exists
    for (int i = 0; i < UMF_DEFAULT_SIZE; i++) {
        const char *pname = NULL;
        ret = ops->get_name(NULL, &pname);
        if (ret != UMF_RESULT_SUCCESS) {
            LOG_ERR("Failed to get pool name");
            goto err_pool_init;
        }
        if (CTL_DEFAULT_ENTRIES[i][0] != '\0' && pname &&
            strstr(CTL_DEFAULT_ENTRIES[i], pname)) {

            default_ctl_helper(ops, pool->pool_priv, CTL_DEFAULT_ENTRIES[i],
                               CTL_DEFAULT_VALUES[i]);
        }
    }

    *hPool = pool;
    LOG_INFO("Memory pool created: %p", (void *)pool);
    return UMF_RESULT_SUCCESS;

err_pool_init:
    utils_mutex_destroy_not_free(&pool->lock);
err_lock_init:
    if (!(flags & UMF_POOL_CREATE_FLAG_DISABLE_TRACKING)) {
        umfMemoryProviderDestroy(pool->provider);
    }
err_provider_create:
    umf_ba_global_free(pool);
    return ret;
}

umf_result_t umfPoolDestroy(umf_memory_pool_handle_t hPool) {
    if (umf_ba_global_is_destroyed()) {
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    umf_result_t ret = hPool->ops.finalize(hPool->pool_priv);

    umf_memory_provider_handle_t hUpstreamProvider = NULL;
    umfPoolGetMemoryProvider(hPool, &hUpstreamProvider);

    if (!(hPool->flags & UMF_POOL_CREATE_FLAG_DISABLE_TRACKING)) {
        // Destroy tracking provider.
        umf_result_t ret2 = umfMemoryProviderDestroy(hPool->provider);
        if (ret == UMF_RESULT_SUCCESS) {
            ret = ret2;
        }
    }

    if (hPool->flags & UMF_POOL_CREATE_FLAG_OWN_PROVIDER) {
        // Destroy associated memory provider.
        umf_result_t ret2 = umfMemoryProviderDestroy(hUpstreamProvider);
        if (ret == UMF_RESULT_SUCCESS) {
            ret = ret2;
        }
    }

    utils_mutex_destroy_not_free(&hPool->lock);

    LOG_INFO("Memory pool destroyed: %p", (void *)hPool);

    // TODO: this free keeps memory in base allocator, so it can lead to OOM in some scenarios (it should be optimized)
    umf_ba_global_free(hPool);
    return ret;
}

umf_result_t umfFree(void *ptr) {
    umf_memory_pool_handle_t hPool = NULL;
    umf_result_t ret = umfPoolByPtr(ptr, &hPool);
    if (ret == UMF_RESULT_SUCCESS) {
        LOG_DEBUG("calling umfPoolFree(pool=%p, ptr=%p) ...", (void *)hPool,
                  ptr);
        return umfPoolFree(hPool, ptr);
    }
    return ret;
}

umf_result_t umfPoolByPtr(const void *ptr, umf_memory_pool_handle_t *pool) {
    UMF_CHECK(pool != NULL, UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK(ptr != NULL, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    umf_memory_properties_handle_t props = NULL;
    umf_result_t ret = umfGetMemoryPropertiesHandle(ptr, &props);
    if (ret != UMF_RESULT_SUCCESS || props == NULL || props->pool == NULL) {
        *pool = NULL;
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    *pool = props->pool;
    return UMF_RESULT_SUCCESS;
}

umf_result_t umfPoolGetMemoryProvider(umf_memory_pool_handle_t hPool,
                                      umf_memory_provider_handle_t *hProvider) {
    UMF_CHECK((hPool != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((hProvider != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);

    if (hPool->flags & UMF_POOL_CREATE_FLAG_DISABLE_TRACKING) {
        *hProvider = hPool->provider;
    } else {
        umfTrackingMemoryProviderGetUpstreamProvider(
            umfMemoryProviderGetPriv(hPool->provider), hProvider);
    }

    return UMF_RESULT_SUCCESS;
}

umf_result_t umfPoolGetName(umf_memory_pool_handle_t pool, const char **name) {
    UMF_CHECK((pool != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((name != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    return pool->ops.get_name(pool->pool_priv, name);
}

umf_result_t umfPoolCreate(const umf_memory_pool_ops_t *ops,
                           umf_memory_provider_handle_t provider,
                           const void *params, umf_pool_create_flags_t flags,
                           umf_memory_pool_handle_t *hPool) {
    libumfInit();

    umf_result_t ret =
        umfPoolCreateInternal(ops, provider, params, flags, hPool);
    if (ret != UMF_RESULT_SUCCESS) {
        return ret;
    }
    assert(*hPool != NULL);

    return UMF_RESULT_SUCCESS;
}

void *umfPoolMalloc(umf_memory_pool_handle_t hPool, size_t size) {
    UMF_CHECK((hPool != NULL), NULL);
    void *ret = hPool->ops.malloc(hPool->pool_priv, size);
    if (!ret) {
        return NULL;
    }

    utils_atomic_increment_size_t(&hPool->stats.alloc_count);
    return ret;
}

void *umfPoolAlignedMalloc(umf_memory_pool_handle_t hPool, size_t size,
                           size_t alignment) {
    UMF_CHECK((hPool != NULL), NULL);
    void *ret = hPool->ops.aligned_malloc(hPool->pool_priv, size, alignment);
    if (!ret) {
        return NULL;
    }

    utils_atomic_increment_size_t(&hPool->stats.alloc_count);
    return ret;
}

void *umfPoolCalloc(umf_memory_pool_handle_t hPool, size_t num, size_t size) {
    UMF_CHECK((hPool != NULL), NULL);
    void *ret = hPool->ops.calloc(hPool->pool_priv, num, size);
    if (!ret) {
        return NULL;
    }

    utils_atomic_increment_size_t(&hPool->stats.alloc_count);
    return ret;
}

void *umfPoolRealloc(umf_memory_pool_handle_t hPool, void *ptr, size_t size) {
    UMF_CHECK((hPool != NULL), NULL);
    void *ret = hPool->ops.realloc(hPool->pool_priv, ptr, size);
    if (size == 0 && ret == NULL && ptr != NULL) { // this is free(ptr)
        utils_atomic_decrement_size_t(&hPool->stats.alloc_count);
    } else if (ptr == NULL && ret != NULL) { // this is malloc(size)
        utils_atomic_increment_size_t(&hPool->stats.alloc_count);
    }
    return ret;
}

umf_result_t umfPoolMallocUsableSize(umf_memory_pool_handle_t hPool,
                                     const void *ptr, size_t *size) {
    UMF_CHECK((hPool != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    return hPool->ops.malloc_usable_size(hPool->pool_priv, ptr, size);
}

umf_result_t umfPoolFree(umf_memory_pool_handle_t hPool, void *ptr) {
    UMF_CHECK((hPool != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    umf_result_t ret = hPool->ops.free(hPool->pool_priv, ptr);

    if (ret != UMF_RESULT_SUCCESS) {
        return ret;
    }
    if (ptr != NULL) {
        utils_atomic_decrement_size_t(&hPool->stats.alloc_count);
    }
    return ret;
}

umf_result_t umfPoolGetLastAllocationError(umf_memory_pool_handle_t hPool) {
    UMF_CHECK((hPool != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    return hPool->ops.get_last_allocation_error(hPool->pool_priv);
}

umf_result_t umfPoolSetTag(umf_memory_pool_handle_t hPool, void *tag,
                           void **oldTag) {
    UMF_CHECK((hPool != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    utils_mutex_lock(&hPool->lock);
    if (oldTag) {
        *oldTag = hPool->tag;
    }
    hPool->tag = tag;
    utils_mutex_unlock(&hPool->lock);
    return UMF_RESULT_SUCCESS;
}

umf_result_t umfPoolGetTag(umf_memory_pool_handle_t hPool, void **tag) {
    UMF_CHECK((hPool != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    UMF_CHECK((tag != NULL), UMF_RESULT_ERROR_INVALID_ARGUMENT);
    utils_mutex_lock(&hPool->lock);
    *tag = hPool->tag;
    utils_mutex_unlock(&hPool->lock);
    return UMF_RESULT_SUCCESS;
}
