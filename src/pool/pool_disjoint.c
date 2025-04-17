/*
 * Copyright (C) 2022-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include <umf/memory_pool.h>
#include <umf/memory_pool_ops.h>
#include <umf/memory_provider.h>

#include "base_alloc_global.h"
#include "pool_disjoint_internal.h"
#include "provider/provider_tracking.h"
#include "uthash/utlist.h"
#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_log.h"
#include "utils_math.h"

// Temporary solution for disabling memory poisoning. This is needed because
// AddressSanitizer does not support memory poisoning for GPU allocations.
// More info: https://github.com/oneapi-src/unified-memory-framework/issues/634
#ifndef POISON_MEMORY
#undef __SANITIZE_ADDRESS__
#endif
#include "utils_sanitizers.h"

// Forward declarations
static void bucket_update_stats(bucket_t *bucket, int in_use, int in_pool);
static bool bucket_can_pool(bucket_t *bucket);
static slab_list_item_t *bucket_get_avail_slab(bucket_t *bucket,
                                               bool *from_pool);

static __TLS umf_result_t TLS_last_allocation_error;

// Allocations are a minimum of 4KB/64KB/2MB even when a smaller size is
// requested. The implementation distinguishes between allocations of size
// ChunkCutOff = (minimum-alloc-size / 2) and those that are larger.
// Allocation requests smaller than ChunkCutoff use chunks taken from a single
// coarse-grain allocation. Thus, for example, for a 64KB minimum allocation
// size, and 8-byte allocations, only 1 in ~8000 requests results in a new
// coarse-grain allocation. Freeing results only in a chunk of a larger
// allocation to be marked as available and no real return to the system. An
// allocation is returned to the system only when all chunks in the larger
// allocation are freed by the program. Allocations larger than ChunkCutOff use
// a separate coarse-grain allocation for each request. These are subject to
// "pooling". That is, when such an allocation is freed by the program it is
// retained in a pool. The pool is available for future allocations, which means
// there are fewer actual coarse-grain allocations/deallocations.

// The largest size which is allocated via the allocator.
// Allocations with size > CutOff bypass the pool and
// go directly to the provider.
static const size_t CutOff = (size_t)1 << 31; // 2GB

static size_t bucket_slab_min_size(bucket_t *bucket) {
    return bucket->pool->params.slab_min_size;
}

static size_t bucket_slab_alloc_size(bucket_t *bucket) {
    return utils_max(bucket->size, bucket_slab_min_size(bucket));
}

static slab_t *create_slab(bucket_t *bucket) {
    assert(bucket);

    umf_result_t res = UMF_RESULT_SUCCESS;
    umf_memory_provider_handle_t provider = bucket->pool->provider;

    size_t num_chunks_total =
        utils_max(bucket_slab_min_size(bucket) / bucket->size, 1);

    // Calculate the number of 64-bit words needed.
    size_t num_words =
        (num_chunks_total + CHUNK_BITMAP_SIZE - 1) / CHUNK_BITMAP_SIZE;

    slab_t *slab = umf_ba_global_alloc(sizeof(*slab) +
                                       num_words * sizeof(slab->chunks[0]));
    if (slab == NULL) {
        LOG_ERR("allocation of new slab failed!");
        return NULL;
    }

    slab->num_chunks_allocated = 0;
    slab->bucket = bucket;

    slab->iter.val = slab;
    slab->iter.prev = slab->iter.next = NULL;

    slab->num_chunks_total = num_chunks_total;
    slab->num_words = num_words;

    // set all chunks as free
    memset(slab->chunks, ~0, num_words * sizeof(slab->chunks[0]));
    if (num_chunks_total % CHUNK_BITMAP_SIZE) {
        // clear remaining bits
        slab->chunks[num_words - 1] =
            ((1ULL << (num_chunks_total % CHUNK_BITMAP_SIZE)) - 1);
    }

    // if slab_min_size is not a multiple of bucket size, we would have some
    // padding at the end of the slab
    slab->slab_size = bucket_slab_alloc_size(bucket);

    // TODO not true
    // NOTE: originally slabs memory were allocated without alignment
    // with this registering a slab is simpler and doesn't require multimap
    res = umfMemoryProviderAlloc(provider, slab->slab_size, 0, &slab->mem_ptr);
    if (res != UMF_RESULT_SUCCESS) {
        LOG_ERR("allocation of slab data failed!");
        goto free_slab;
    }

    // raw allocation is not available for user so mark it as inaccessible
    utils_annotate_memory_inaccessible(slab->mem_ptr, slab->slab_size);

    LOG_DEBUG("bucket: %p, slab_size: %zu", (void *)bucket, slab->slab_size);
    return slab;

free_slab:
    umf_ba_global_free(slab);
    return NULL;
}

static void destroy_slab(slab_t *slab) {
    LOG_DEBUG("bucket: %p, slab_size: %zu", (void *)slab->bucket,
              slab->slab_size);

    umf_memory_provider_handle_t provider = slab->bucket->pool->provider;
    umf_result_t res =
        umfMemoryProviderFree(provider, slab->mem_ptr, slab->slab_size);
    if (res != UMF_RESULT_SUCCESS) {
        LOG_ERR("deallocation of slab data failed!");
    }
}

static size_t slab_find_first_available_chunk_idx(const slab_t *slab) {
    for (size_t i = 0; i < slab->num_words; i++) {
        // NOTE: free chunks are represented as set bits
        uint64_t word = slab->chunks[i];
        if (word != 0) {
            size_t bit_index = utils_lsb64(word);
            size_t free_chunk = i * CHUNK_BITMAP_SIZE + bit_index;
            return free_chunk;
        }
    }

    // No free chunk was found.
    return SIZE_MAX;
}

static void *slab_get_chunk(slab_t *slab) {
    // free chunk must exist, otherwise we would have allocated another slab
    const size_t chunk_idx = slab_find_first_available_chunk_idx(slab);
    assert(chunk_idx != SIZE_MAX);

    void *free_chunk =
        (void *)((uintptr_t)slab->mem_ptr + chunk_idx * slab->bucket->size);

    // mark chunk as used
    slab_set_chunk_bit(slab, chunk_idx, false);
    slab->num_chunks_allocated += 1;

    return free_chunk;
}

static void *slab_get(const slab_t *slab) { return slab->mem_ptr; }
static void *slab_get_end(const slab_t *slab) {
    return (void *)((uintptr_t)slab->mem_ptr +
                    bucket_slab_min_size(slab->bucket));
}

static void slab_free_chunk(slab_t *slab, void *ptr) {
    // This method should be called through bucket (since we might remove the
    // slab as a result), therefore all locks are done on bucket level.

    // Make sure that we're in the right slab
    assert(ptr >= slab_get(slab) && ptr < slab_get_end(slab));

    // Get the chunk index
    uintptr_t ptr_diff = (uintptr_t)ptr - (uintptr_t)slab->mem_ptr;
    assert((ptr_diff % slab->bucket->size) == 0);
    size_t chunk_idx = ptr_diff / slab->bucket->size;

    // Make sure that the chunk was allocated
    assert(slab_read_chunk_bit(slab, chunk_idx) == 0 && "double free detected");
    slab_set_chunk_bit(slab, chunk_idx, true);
    slab->num_chunks_allocated -= 1;
}

static bool slab_has_avail(const slab_t *slab) {
    return slab->num_chunks_allocated < slab->num_chunks_total;
}

static umf_result_t pool_register_slab(disjoint_pool_t *pool, slab_t *slab) {
    critnib *slabs = pool->known_slabs;

    // NOTE: changed vs original DisjointPool implementation - currently slab
    // is already aligned to bucket size.
    void *slab_addr = slab_get(slab);
    // TODO ASSERT_IS_ALIGNED((uintptr_t)slab_addr, bucket->size);
    LOG_DEBUG("slab: %p, start: %p", (void *)slab, slab_addr);

    // NOTE: we don't need to lock the slabs map as the critnib already has a
    // lock inside it
    int ret = critnib_insert(slabs, (uintptr_t)slab_addr, slab, 0);
    umf_result_t res = UMF_RESULT_SUCCESS;
    if (ret == ENOMEM) {
        LOG_ERR("register failed because of out of memory!");
        res = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    } else if (ret == EEXIST) {
        LOG_ERR("register failed because the address is already registered!");
        res = UMF_RESULT_ERROR_UNKNOWN;
    }

    return res;
}

static umf_result_t pool_unregister_slab(disjoint_pool_t *pool, slab_t *slab) {
    critnib *slabs = pool->known_slabs;

    void *slab_addr = slab_get(slab);
    // TODO ASSERT_IS_ALIGNED((uintptr_t)slab_addr, bucket->size);
    LOG_DEBUG("slab: %p, start: %p", (void *)slab, slab_addr);

    critnib_remove(slabs, (uintptr_t)slab_addr);

    return UMF_RESULT_SUCCESS;
}

static bucket_t *
create_bucket(size_t sz, disjoint_pool_t *pool,
              umf_disjoint_pool_shared_limits_handle_t shared_limits) {

    bucket_t *bucket = umf_ba_global_alloc(sizeof(*bucket));
    if (bucket == NULL) {
        LOG_ERR("allocation of new bucket failed!");
        return NULL;
    }

    memset(bucket, 0, sizeof(*bucket));
    bucket->size = sz;
    bucket->pool = pool;
    bucket->shared_limits = shared_limits;

    utils_mutex_init(&bucket->bucket_lock);
    return bucket;
}

static void destroy_bucket(bucket_t *bucket) {
    // use an extra tmp to store the next iterator before destroying the slab
    slab_list_item_t *it = NULL, *tmp = NULL;
    LL_FOREACH_SAFE(bucket->available_slabs, it, tmp) {
        LL_DELETE(bucket->available_slabs, it);
        destroy_slab(it->val);
    }

    LL_FOREACH_SAFE(bucket->unavailable_slabs, it, tmp) {
        LL_DELETE(bucket->unavailable_slabs, it);
        destroy_slab(it->val);
    }

    utils_mutex_destroy_not_free(&bucket->bucket_lock);
    umf_ba_global_free(bucket);
}

static size_t slab_get_num_free_chunks(const slab_t *slab) {
    return slab->num_chunks_total - slab->num_chunks_allocated;
}

// NOTE: this function must be called under bucket->bucket_lock
static void bucket_free_chunk(bucket_t *bucket, void *ptr, slab_t *slab,
                              bool *to_pool) {
    slab_free_chunk(slab, ptr);

    // in case if the slab was previously full and now has single available
    // chunk, it should be moved to the list of available slabs
    if (slab_get_num_free_chunks(slab) == 1) {
        slab_list_item_t *slab_it = &slab->iter;
        assert(slab_it->val != NULL);
        DL_DELETE(bucket->unavailable_slabs, slab_it);
        DL_PREPEND(bucket->available_slabs, slab_it);
        bucket->available_slabs_num++;
    }

    // check if slab is empty, and pool it if we can
    if (slab->num_chunks_allocated == 0) {
        // The slab is now empty.
        // If the pool has capacity then put the slab in the pool.
        // The to_pool parameter indicates whether the slab will be put in the
        // pool or freed.
        *to_pool = bucket_can_pool(bucket);
        if (*to_pool == false) {
            // remove slab
            slab_list_item_t *slab_it = &slab->iter;
            assert(slab_it->val != NULL);
            pool_unregister_slab(bucket->pool, slab_it->val);
            DL_DELETE(bucket->available_slabs, slab_it);
            assert(bucket->available_slabs_num > 0);
            bucket->available_slabs_num--;
            destroy_slab(slab_it->val);
        }
    } else {
        // return this chunk to the pool
        *to_pool = true;
    }
}

// NOTE: this function must be called under bucket->bucket_lock
static void *bucket_get_free_chunk(bucket_t *bucket, bool *from_pool) {
    slab_list_item_t *slab_it = bucket_get_avail_slab(bucket, from_pool);
    if (slab_it == NULL) {
        return NULL;
    }

    void *free_chunk = slab_get_chunk(slab_it->val);

    // if we allocated last free chunk from the slab and now it is full, move
    // it to unavailable slabs and update its iterator
    if (!(slab_has_avail(slab_it->val))) {
        DL_DELETE(bucket->available_slabs, slab_it);
        bucket->available_slabs_num--;
        slab_it->prev = NULL;
        DL_PREPEND(bucket->unavailable_slabs, slab_it);
    }

    return free_chunk;
}

static size_t bucket_chunk_cut_off(bucket_t *bucket) {
    return bucket_slab_min_size(bucket) / 2;
}

static slab_t *bucket_create_slab(bucket_t *bucket) {
    slab_t *slab = create_slab(bucket);
    if (slab == NULL) {
        LOG_ERR("create_slab failed!")
        return NULL;
    }

    umf_result_t res = pool_register_slab(bucket->pool, slab);
    if (res != UMF_RESULT_SUCCESS) {
        LOG_ERR("slab_reg failed!")
        destroy_slab(slab);
        return NULL;
    }

    DL_PREPEND(bucket->available_slabs, &slab->iter);
    bucket->available_slabs_num++;
    bucket_update_stats(bucket, 1, 0);

    return slab;
}

static slab_list_item_t *bucket_get_avail_slab(bucket_t *bucket,
                                               bool *from_pool) {
    if (bucket->available_slabs == NULL) {
        bucket_create_slab(bucket);
        *from_pool = false;
    } else {
        slab_t *slab = bucket->available_slabs->val;
        // Allocation from existing slab is treated as from pool for statistics.
        *from_pool = true;
        if (slab->num_chunks_allocated == 0) {
            assert(bucket->chunked_slabs_in_pool > 0);
            // If this was an empty slab, it was in the pool.
            // Now it is no longer in the pool, so update count.
            --bucket->chunked_slabs_in_pool;
            uint64_t size_to_sub = bucket_slab_alloc_size(bucket);
            uint64_t old_size = utils_fetch_and_sub_u64(
                &bucket->shared_limits->total_size, size_to_sub);
            (void)old_size;
            assert(old_size >= size_to_sub);
            bucket_update_stats(bucket, 1, -1);
        }
    }

    return bucket->available_slabs;
}

static size_t bucket_max_pooled_slabs(bucket_t *bucket) {
    // For small buckets where slabs are split to chunks, just one pooled slab is sufficient.
    // For larger buckets, the capacity could be more and is adjustable.
    if (bucket->size <= bucket_chunk_cut_off(bucket)) {
        return 1;
    } else {
        return bucket->pool->params.capacity;
    }
}

static void bucket_update_stats(bucket_t *bucket, int in_use, int in_pool) {
    if (bucket->pool->params.pool_trace == 0) {
        return;
    }

    bucket->curr_slabs_in_use += in_use;
    bucket->max_slabs_in_use =
        utils_max(bucket->curr_slabs_in_use, bucket->max_slabs_in_use);

    bucket->curr_slabs_in_pool += in_pool;
    bucket->max_slabs_in_pool =
        utils_max(bucket->curr_slabs_in_pool, bucket->max_slabs_in_pool);

    // Increment or decrement current pool sizes based on whether
    // slab was added to or removed from pool.
    bucket->pool->params.cur_pool_size +=
        in_pool * bucket_slab_alloc_size(bucket);
}

static bool bucket_can_pool(bucket_t *bucket) {
    size_t new_free_slabs_in_bucket;

    new_free_slabs_in_bucket = bucket->chunked_slabs_in_pool + 1;

    // we keep at most params.capacity slabs in the pool
    if (bucket_max_pooled_slabs(bucket) >= new_free_slabs_in_bucket) {

        uint64_t size_to_add = bucket_slab_alloc_size(bucket);
        size_t previous_size = utils_fetch_and_add_u64(
            &bucket->shared_limits->total_size, size_to_add);

        if (previous_size + size_to_add <= bucket->shared_limits->max_size) {
            ++bucket->chunked_slabs_in_pool;
            bucket_update_stats(bucket, -1, 1);
            return true;
        } else {
            uint64_t old = utils_fetch_and_sub_u64(
                &bucket->shared_limits->total_size, size_to_add);
            (void)old;
            assert(old >= size_to_add);
        }
    }

    bucket_update_stats(bucket, -1, 0);
    return false;
}

static size_t size_to_idx(disjoint_pool_t *pool, size_t size) {
    assert(size <= CutOff && "Unexpected size");
    assert(size > 0 && "Unexpected size");

    size_t min_bucket_size = (size_t)1 << pool->min_bucket_size_exp;
    if (size < min_bucket_size) {
        return 0;
    }

    // get the position of the leftmost set bit
    size_t position = utils_msb64(size);

    bool is_power_of_2 = IS_POWER_OF_2(size);
    bool larger_than_halfway_between_powers_of_2 =
        !is_power_of_2 &&
        (bool)((size - 1) & ((uint64_t)(1) << (position - 1)));
    size_t index = (position - pool->min_bucket_size_exp) * 2 +
                   (int)(!is_power_of_2) +
                   (int)larger_than_halfway_between_powers_of_2;

    return index;
}

static umf_disjoint_pool_shared_limits_t *
disjoint_pool_get_limits(disjoint_pool_t *pool) {
    if (pool->params.shared_limits) {
        return pool->params.shared_limits;
    } else {
        return pool->default_shared_limits;
    }
}

static bucket_t *disjoint_pool_find_bucket(disjoint_pool_t *pool, size_t size) {
    size_t calculated_idx = size_to_idx(pool, size);
    return pool->buckets[calculated_idx];
}

static void disjoint_pool_print_stats(disjoint_pool_t *pool) {
    size_t high_bucket_size = 0;
    size_t high_peak_slabs_in_use = 0;
    const char *name = pool->params.name;

    LOG_DEBUG("\"%s\" pool memory statistics", name);
    LOG_DEBUG("%14s %12s %12s %18s %20s %21s", "Bucket Size", "Allocs", "Frees",
              "Allocs from Pool", "Peak Slabs in Use", "Peak Slabs in Pool");

    for (size_t i = 0; i < pool->buckets_num; i++) {
        bucket_t *bucket = pool->buckets[i];
        // lock bucket before accessing its stats
        utils_mutex_lock(&bucket->bucket_lock);

        if (bucket->alloc_count) {
            LOG_DEBUG("%14zu %12zu %12zu %18zu %20zu %21zu", bucket->size,
                      bucket->alloc_count, bucket->free_count,
                      bucket->alloc_pool_count, bucket->max_slabs_in_use,
                      bucket->max_slabs_in_pool);
            high_bucket_size =
                utils_max(bucket_slab_alloc_size(bucket), high_bucket_size);
        }

        high_peak_slabs_in_use =
            utils_max(bucket->max_slabs_in_use, high_peak_slabs_in_use);

        utils_mutex_unlock(&bucket->bucket_lock);
    }

    LOG_DEBUG("current pool size: %" PRIu64,
              disjoint_pool_get_limits(pool)->total_size);
    LOG_DEBUG("suggested setting=;%c%s:%zu,%zu,64K", (char)tolower(name[0]),
              (name + 1), high_bucket_size, high_peak_slabs_in_use);
}

static void *disjoint_pool_allocate(disjoint_pool_t *pool, size_t size) {
    if (size == 0) {
        return NULL;
    }

    void *ptr = NULL;

    if (size > pool->params.max_poolable_size) {
        umf_result_t ret =
            umfMemoryProviderAlloc(pool->provider, size, 0, &ptr);
        if (ret != UMF_RESULT_SUCCESS) {
            TLS_last_allocation_error = ret;
            LOG_ERR("allocation from the memory provider failed");
            return NULL;
        }

        utils_annotate_memory_undefined(ptr, size);
        return ptr;
    }

    bucket_t *bucket = disjoint_pool_find_bucket(pool, size);

    utils_mutex_lock(&bucket->bucket_lock);

    bool from_pool = false;
    ptr = bucket_get_free_chunk(bucket, &from_pool);

    if (ptr == NULL) {
        TLS_last_allocation_error = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        utils_mutex_unlock(&bucket->bucket_lock);
        return NULL;
    }

    if (pool->params.pool_trace > 1) {
        // update stats
        ++bucket->alloc_count;
        if (from_pool) {
            ++bucket->alloc_pool_count;
        }
    }

    utils_mutex_unlock(&bucket->bucket_lock);

    if (pool->params.pool_trace > 2) {
        LOG_DEBUG("Allocated %8zu %s bytes from %s -> %p", size,
                  pool->params.name, (from_pool ? "pool" : "provider"), ptr);
    }

    VALGRIND_DO_MEMPOOL_ALLOC(pool, ptr, size);
    utils_annotate_memory_undefined(ptr, bucket->size);
    return ptr;
}

static void free_slab(void *unused, void *slab) {
    (void)unused;
    if (slab) {
        umf_ba_global_free(slab);
    }
}

umf_result_t disjoint_pool_initialize(umf_memory_provider_handle_t provider,
                                      const void *params, void **ppPool) {
    // TODO set defaults when user pass the NULL as params
    if (!provider || !params || !ppPool) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    const umf_disjoint_pool_params_t *dp_params = params;

    // min_bucket_size parameter must be a power of 2 for bucket sizes
    // to generate correctly.
    if (!dp_params->min_bucket_size ||
        !IS_POWER_OF_2(dp_params->min_bucket_size)) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    disjoint_pool_t *disjoint_pool =
        umf_ba_global_alloc(sizeof(*disjoint_pool));
    if (disjoint_pool == NULL) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    VALGRIND_DO_CREATE_MEMPOOL(disjoint_pool, 0, 0);

    disjoint_pool->provider = provider;
    disjoint_pool->params = *dp_params;

    disjoint_pool->known_slabs = critnib_new(free_slab, NULL);
    if (disjoint_pool->known_slabs == NULL) {
        goto err_free_disjoint_pool;
    }

    // Generate buckets sized such as: 64, 96, 128, 192, ..., CutOff.
    // Powers of 2 and the value halfway between the powers of 2.
    size_t Size1 = disjoint_pool->params.min_bucket_size;

    // min_bucket_size cannot be larger than CutOff.
    Size1 = utils_min(Size1, CutOff);

    // Buckets sized smaller than the bucket default size- 8 aren't needed.
    Size1 = utils_max(Size1, UMF_DISJOINT_POOL_MIN_BUCKET_DEFAULT_SIZE);

    // Calculate the exponent for min_bucket_size used for finding buckets.
    disjoint_pool->min_bucket_size_exp = (size_t)utils_msb64(Size1);
    disjoint_pool->default_shared_limits =
        umfDisjointPoolSharedLimitsCreate(SIZE_MAX);
    if (disjoint_pool->default_shared_limits == NULL) {
        goto err_free_known_slabs;
    }

    // count number of buckets, start from 1
    disjoint_pool->buckets_num = 1;
    size_t Size2 = Size1 + Size1 / 2;
    size_t ts2 = Size2, ts1 = Size1;
    while (Size2 < CutOff) {
        disjoint_pool->buckets_num += 2;
        Size2 *= 2;
    }

    disjoint_pool->buckets = umf_ba_global_alloc(
        sizeof(*disjoint_pool->buckets) * disjoint_pool->buckets_num);
    if (disjoint_pool->buckets == NULL) {
        goto err_free_shared_limits;
    }

    size_t i = 0;
    Size1 = ts1;
    Size2 = ts2;
    for (; Size2 < CutOff; Size1 *= 2, Size2 *= 2, i += 2) {
        disjoint_pool->buckets[i] = create_bucket(
            Size1, disjoint_pool, disjoint_pool_get_limits(disjoint_pool));
        disjoint_pool->buckets[i + 1] = create_bucket(
            Size2, disjoint_pool, disjoint_pool_get_limits(disjoint_pool));
    }
    disjoint_pool->buckets[i] = create_bucket(
        CutOff, disjoint_pool, disjoint_pool_get_limits(disjoint_pool));

    // check if all buckets were created successfully
    for (i = 0; i < disjoint_pool->buckets_num; i++) {
        if (disjoint_pool->buckets[i] == NULL) {
            goto err_free_buckets;
        }
    }

    umf_result_t ret = umfMemoryProviderGetMinPageSize(
        provider, NULL, &disjoint_pool->provider_min_page_size);
    if (ret != UMF_RESULT_SUCCESS) {
        disjoint_pool->provider_min_page_size = 0;
    }

    *ppPool = (void *)disjoint_pool;

    return UMF_RESULT_SUCCESS;

err_free_buckets:
    for (i = 0; i < disjoint_pool->buckets_num; i++) {
        if (disjoint_pool->buckets[i] != NULL) {
            destroy_bucket(disjoint_pool->buckets[i]);
        }
    }
    umf_ba_global_free(disjoint_pool->buckets);

err_free_shared_limits:
    umfDisjointPoolSharedLimitsDestroy(disjoint_pool->default_shared_limits);

err_free_known_slabs:
    critnib_delete(disjoint_pool->known_slabs);

err_free_disjoint_pool:
    umf_ba_global_free(disjoint_pool);

    return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
}

void *disjoint_pool_malloc(void *pool, size_t size) {
    disjoint_pool_t *hPool = (disjoint_pool_t *)pool;
    void *ptr = disjoint_pool_allocate(hPool, size);

    return ptr;
}

void *disjoint_pool_calloc(void *pool, size_t num, size_t size) {
    (void)pool;
    (void)num;
    (void)size;

    // Not supported
    TLS_last_allocation_error = UMF_RESULT_ERROR_NOT_SUPPORTED;
    return NULL;
}

void *disjoint_pool_realloc(void *pool, void *ptr, size_t size) {
    (void)pool;
    (void)ptr;
    (void)size;

    // Not supported
    TLS_last_allocation_error = UMF_RESULT_ERROR_NOT_SUPPORTED;
    return NULL;
}

void *disjoint_pool_aligned_malloc(void *pool, size_t size, size_t alignment) {
    disjoint_pool_t *disjoint_pool = (disjoint_pool_t *)pool;

    void *ptr = NULL;

    if (size == 0) {
        return NULL;
    }

    if (alignment <= 1) {
        return disjoint_pool_allocate(pool, size);
    }

    size_t aligned_size;
    if (alignment <= disjoint_pool->provider_min_page_size) {
        // This allocation will be served from a Bucket which size is multiple
        // of Alignment and Slab address is aligned to provider_min_page_size
        // so the address will be properly aligned.
        aligned_size = (size > 1) ? ALIGN_UP_SAFE(size, alignment) : alignment;
    } else {
        // Slabs are only aligned to provider_min_page_size, we need to compensate
        // for that in case the allocation is within pooling limit.
        // TODO: consider creating properly-aligned Slabs on demand
        aligned_size = size + alignment - 1;
    }

    // Check if requested allocation size is within pooling limit.
    // If not, just request aligned pointer from the system.
    if (aligned_size > disjoint_pool->params.max_poolable_size) {

        umf_result_t ret = umfMemoryProviderAlloc(disjoint_pool->provider, size,
                                                  alignment, &ptr);
        if (ret != UMF_RESULT_SUCCESS) {
            TLS_last_allocation_error = ret;
            LOG_ERR("allocation from the memory provider failed");
            return NULL;
        }

        assert(ptr);
        utils_annotate_memory_undefined(ptr, size);
        return ptr;
    }

    bool from_pool = false;
    bucket_t *bucket = disjoint_pool_find_bucket(pool, aligned_size);

    utils_mutex_lock(&bucket->bucket_lock);

    ptr = bucket_get_free_chunk(bucket, &from_pool);

    if (ptr == NULL) {
        TLS_last_allocation_error = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        utils_mutex_unlock(&bucket->bucket_lock);
        return NULL;
    }

    if (disjoint_pool->params.pool_trace > 1) {
        // update stats
        ++bucket->alloc_count;
        if (from_pool) {
            ++bucket->alloc_pool_count;
        }
    }

    void *aligned_ptr = (void *)ALIGN_UP_SAFE((size_t)ptr, alignment);
    size_t diff = (ptrdiff_t)aligned_ptr - (ptrdiff_t)ptr;
    size_t real_size = bucket->size - diff;
    VALGRIND_DO_MEMPOOL_ALLOC(disjoint_pool, aligned_ptr, real_size);
    utils_annotate_memory_undefined(aligned_ptr, real_size);

    utils_mutex_unlock(&bucket->bucket_lock);

    if (disjoint_pool->params.pool_trace > 2) {
        LOG_DEBUG("Allocated %8zu %s bytes aligned at %zu from %s -> %p", size,
                  disjoint_pool->params.name, alignment,
                  (from_pool ? "pool" : "provider"), ptr);
    }

    return aligned_ptr;
}

static size_t get_chunk_idx(const void *ptr, slab_t *slab) {
    return (((uintptr_t)ptr - (uintptr_t)slab->mem_ptr) / slab->bucket->size);
}

static void *get_unaligned_ptr(size_t chunk_idx, slab_t *slab) {
    return (void *)((uintptr_t)slab->mem_ptr + chunk_idx * slab->bucket->size);
}

size_t disjoint_pool_malloc_usable_size(void *pool, const void *ptr) {
    disjoint_pool_t *disjoint_pool = (disjoint_pool_t *)pool;
    if (ptr == NULL) {
        return 0;
    }

    // check if given pointer is allocated inside any Disjoint Pool slab
    slab_t *slab =
        (slab_t *)critnib_find_le(disjoint_pool->known_slabs, (uintptr_t)ptr);
    if (slab == NULL || ptr >= slab_get_end(slab)) {
        // memory comes directly from the provider
        umf_alloc_info_t allocInfo = {NULL, 0, NULL};
        umf_result_t ret = umfMemoryTrackerGetAllocInfo(ptr, &allocInfo);
        if (ret != UMF_RESULT_SUCCESS) {
            return 0;
        }

        return allocInfo.baseSize;
    }
    // Get the unaligned pointer
    // NOTE: the base pointer slab->mem_ptr needn't to be aligned to bucket size
    size_t chunk_idx = get_chunk_idx(ptr, slab);
    void *unaligned_ptr = get_unaligned_ptr(chunk_idx, slab);

    ptrdiff_t diff = (ptrdiff_t)ptr - (ptrdiff_t)unaligned_ptr;

    return slab->bucket->size - diff;
}

umf_result_t disjoint_pool_free(void *pool, void *ptr) {
    disjoint_pool_t *disjoint_pool = (disjoint_pool_t *)pool;
    if (ptr == NULL) {
        return UMF_RESULT_SUCCESS;
    }

    // check if given pointer is allocated inside any Disjoint Pool slab
    slab_t *slab =
        (slab_t *)critnib_find_le(disjoint_pool->known_slabs, (uintptr_t)ptr);

    if (slab == NULL || ptr >= slab_get_end(slab)) {

        // regular free
        umf_alloc_info_t allocInfo = {NULL, 0, NULL};
        umf_result_t ret = umfMemoryTrackerGetAllocInfo(ptr, &allocInfo);
        if (ret != UMF_RESULT_SUCCESS) {
            TLS_last_allocation_error = ret;
            LOG_ERR("failed to get allocation info from the memory tracker");
            return ret;
        }

        size_t size = allocInfo.baseSize;
        umf_memory_provider_handle_t provider = disjoint_pool->provider;
        ret = umfMemoryProviderFree(provider, ptr, size);
        if (ret != UMF_RESULT_SUCCESS) {
            TLS_last_allocation_error = ret;
            LOG_ERR("deallocation from the memory provider failed");
        }

        return ret;
    }

    bool to_pool = false;

    if (ptr < slab_get(slab) || ptr >= slab_get_end(slab)) {
        assert(0);
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    // The slab object won't be deleted until it's removed from the map which is
    // protected by the lock, so it's safe to access it here.

    bucket_t *bucket = slab->bucket;

    utils_mutex_lock(&bucket->bucket_lock);
    VALGRIND_DO_MEMPOOL_FREE(pool, ptr);

    // Get the unaligned pointer
    // NOTE: the base pointer slab->mem_ptr needn't to be aligned to bucket size
    size_t chunk_idx = get_chunk_idx(ptr, slab);
    void *unaligned_ptr = get_unaligned_ptr(chunk_idx, slab);

    utils_annotate_memory_inaccessible(unaligned_ptr, bucket->size);
    bucket_free_chunk(bucket, unaligned_ptr, slab, &to_pool);

    if (disjoint_pool->params.pool_trace > 1) {
        bucket->free_count++;
    }

    utils_mutex_unlock(&bucket->bucket_lock);

    if (disjoint_pool->params.pool_trace > 2) {
        const char *name = disjoint_pool->params.name;
        LOG_DEBUG("freed %s %p to %s, current total pool size: %" PRIu64
                  ", current "
                  "pool size for %s: %zu",
                  name, ptr, (to_pool ? "pool" : "provider"),
                  disjoint_pool_get_limits(disjoint_pool)->total_size, name,
                  disjoint_pool->params.cur_pool_size);
    }

    return UMF_RESULT_SUCCESS;
}

umf_result_t disjoint_pool_get_last_allocation_error(void *pool) {
    (void)pool;
    return TLS_last_allocation_error;
}

// Define destructor for use with unique_ptr
void disjoint_pool_finalize(void *pool) {
    disjoint_pool_t *hPool = (disjoint_pool_t *)pool;

    if (hPool->params.pool_trace > 1) {
        disjoint_pool_print_stats(hPool);
    }

    for (size_t i = 0; i < hPool->buckets_num; i++) {
        destroy_bucket(hPool->buckets[i]);
    }

    VALGRIND_DO_DESTROY_MEMPOOL(hPool);

    umfDisjointPoolSharedLimitsDestroy(hPool->default_shared_limits);
    critnib_delete(hPool->known_slabs);

    umf_ba_global_free(hPool);
}

static umf_memory_pool_ops_t UMF_DISJOINT_POOL_OPS = {
    .version = UMF_VERSION_CURRENT,
    .initialize = disjoint_pool_initialize,
    .finalize = disjoint_pool_finalize,
    .malloc = disjoint_pool_malloc,
    .calloc = disjoint_pool_calloc,
    .realloc = disjoint_pool_realloc,
    .aligned_malloc = disjoint_pool_aligned_malloc,
    .malloc_usable_size = disjoint_pool_malloc_usable_size,
    .free = disjoint_pool_free,
    .get_last_allocation_error = disjoint_pool_get_last_allocation_error,
};

const umf_memory_pool_ops_t *umfDisjointPoolOps(void) {
    return &UMF_DISJOINT_POOL_OPS;
}

umf_disjoint_pool_shared_limits_t *
umfDisjointPoolSharedLimitsCreate(size_t max_size) {
    umf_disjoint_pool_shared_limits_t *ptr = umf_ba_global_alloc(sizeof(*ptr));
    if (ptr == NULL) {
        LOG_ERR("cannot allocate memory for disjoint pool shared limits");
        return NULL;
    }
    ptr->max_size = max_size;
    ptr->total_size = 0;
    return ptr;
}

void umfDisjointPoolSharedLimitsDestroy(
    umf_disjoint_pool_shared_limits_t *limits) {
    umf_ba_global_free(limits);
}

umf_result_t
umfDisjointPoolParamsCreate(umf_disjoint_pool_params_handle_t *hParams) {
    static const char *DEFAULT_NAME = "disjoint_pool";

    if (!hParams) {
        LOG_ERR("disjoint pool params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_disjoint_pool_params_handle_t params =
        umf_ba_global_alloc(sizeof(*params));
    if (params == NULL) {
        LOG_ERR("cannot allocate memory for disjoint pool params");
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    *params = (umf_disjoint_pool_params_t){
        .slab_min_size = 0,
        .max_poolable_size = 0,
        .capacity = 0,
        .min_bucket_size = UMF_DISJOINT_POOL_MIN_BUCKET_DEFAULT_SIZE,
        .cur_pool_size = 0,
        .pool_trace = 0,
        .shared_limits = NULL,
        .name = {*DEFAULT_NAME},
    };

    *hParams = params;

    return UMF_RESULT_SUCCESS;
}

umf_result_t
umfDisjointPoolParamsDestroy(umf_disjoint_pool_params_handle_t hParams) {
    // NOTE: dereferencing hParams when BA is already destroyed leads to crash
    if (hParams && !umf_ba_global_is_destroyed()) {
        umf_ba_global_free(hParams);
    }

    return UMF_RESULT_SUCCESS;
}

umf_result_t
umfDisjointPoolParamsSetSlabMinSize(umf_disjoint_pool_params_handle_t hParams,
                                    size_t slabMinSize) {
    if (!hParams) {
        LOG_ERR("disjoint pool params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hParams->slab_min_size = slabMinSize;
    return UMF_RESULT_SUCCESS;
}

umf_result_t umfDisjointPoolParamsSetMaxPoolableSize(
    umf_disjoint_pool_params_handle_t hParams, size_t maxPoolableSize) {
    if (!hParams) {
        LOG_ERR("disjoint pool params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hParams->max_poolable_size = maxPoolableSize;
    return UMF_RESULT_SUCCESS;
}

umf_result_t
umfDisjointPoolParamsSetCapacity(umf_disjoint_pool_params_handle_t hParams,
                                 size_t maxCapacity) {
    if (!hParams) {
        LOG_ERR("disjoint pool params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hParams->capacity = maxCapacity;
    return UMF_RESULT_SUCCESS;
}

umf_result_t
umfDisjointPoolParamsSetMinBucketSize(umf_disjoint_pool_params_handle_t hParams,
                                      size_t minBucketSize) {
    if (!hParams) {
        LOG_ERR("disjoint pool params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    // minBucketSize parameter must be a power of 2 and greater than 0.
    if (minBucketSize == 0 || (minBucketSize & (minBucketSize - 1))) {
        LOG_ERR("minBucketSize must be a power of 2 and greater than 0");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hParams->min_bucket_size = minBucketSize;
    return UMF_RESULT_SUCCESS;
}

umf_result_t
umfDisjointPoolParamsSetTrace(umf_disjoint_pool_params_handle_t hParams,
                              int poolTrace) {
    if (!hParams) {
        LOG_ERR("disjoint pool params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hParams->pool_trace = poolTrace;
    return UMF_RESULT_SUCCESS;
}

umf_result_t umfDisjointPoolParamsSetSharedLimits(
    umf_disjoint_pool_params_handle_t hParams,
    umf_disjoint_pool_shared_limits_handle_t hSharedLimits) {
    if (!hParams) {
        LOG_ERR("disjoint pool params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hParams->shared_limits = hSharedLimits;
    return UMF_RESULT_SUCCESS;
}

umf_result_t
umfDisjointPoolParamsSetName(umf_disjoint_pool_params_handle_t hParams,
                             const char *name) {
    if (!hParams) {
        LOG_ERR("disjoint pool params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    strncpy(hParams->name, name, sizeof(hParams->name) - 1);
    return UMF_RESULT_SUCCESS;
}
