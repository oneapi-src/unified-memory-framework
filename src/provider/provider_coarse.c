/*
    Copyright (c) 2023 Intel Corporation
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at
        http://www.apache.org/licenses/LICENSE-2.0
    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <../utils/utils.h>
#include <provider/provider_coarse.h>

#ifndef BYTE
#define BYTE unsigned char
#endif

static enum umf_result_t coarse_memory_provider_alloc(void *provider,
                                                      size_t size,
                                                      size_t alignment,
                                                      void **resultPtr);

typedef struct block_t {
    size_t size;
    BYTE *data;

    // Origin is the element of the provider's alloc_list that contains the
    // beginning of data in current block. Note that data address could be
    // higher than the origin - this means, that the origin allocation
    // covers current block only partially.
    // If the size of the block is greater than the size of the allocation,
    // it means that there are multiple allocations.
    // Note that provider's alloc_list doesn't use "origin" and "used" fields.
    struct block_t *origin;
    bool used;

    struct block_t *next;
    struct block_t *prev;
} block_t;

static block_t *block_list_add(block_t **head, BYTE *data, size_t size) {
    assert(head);
    assert(data);
    assert(size);

    block_t *block = (block_t *)malloc(sizeof(block_t));
    if (block == NULL) {
        return NULL;
    }

    block->data = data;
    block->size = size;

    if (*head == NULL) {
        // handle case, where the list is empty
        block->prev = NULL;
        block->next = NULL;
        *head = block;
        return block;
    } else if (data < (*head)->data) {
        // case where we have to insert our element in front of the list
        block->prev = NULL;
        block->next = *head;
        (*head)->prev = block;
        *head = block;
        return block;
    }

    // linear search for the suitable place to add new alloc
    // TODO optimize :)
    block_t *curr = *head;
    block_t *prev = NULL;
    while (curr && (curr->data < data)) {
        prev = curr;
        curr = curr->next;
    }

    // else we have to add new alloc between two existing elements or at the
    // end of the list
    assert(prev && prev->data < data);
    block->prev = prev;
    block->next = curr;
    prev->next = block;
    if (curr != NULL) {
        assert(data < curr->data);
        curr->prev = block;
    }

    return block;
}

// Find the alloc that contains data with given offset.
static block_t *alloc_find_origin(block_t *alloc, size_t offset) {
    assert(alloc);

    while (offset >= alloc->size) {
        offset -= alloc->size;
        alloc = alloc->next;
        assert(alloc);
    }

    return alloc;
}

// Merge with prev block if both are unused and have continuous data.
static block_t *block_merge_with_prev(block_t *block) {
    assert(block);

    if (block->prev && block->prev->used == false &&
        (block->prev->data + block->prev->size == block->data)) {
        // set neighbors
        block->prev->next = block->next;
        block->prev->size += block->size;

        if (block->next) {
            block->next->prev = block->prev;
        }

        block_t *to_free = block;
        block = block->prev;
        free(to_free);
    }

    return block;
}

// Merge with next block if both are unused and have continuous data.
static block_t *block_merge_with_next(block_t *block, block_t **head) {
    assert(block);
    assert(head);

    if (block->next && block->next->used == false &&
        (block->data + block->size == block->next->data)) {
        // set neighbors
        block->next->prev = block->prev;
        block->next->size += block->size;

        assert(block->data < block->next->data);
        assert((block->data + block->size) == block->next->data);
        block->next->data = block->data;
        block->next->origin = block->origin;

        if (block->prev) {
            block->prev->next = block->next;
        } else {
            *head = block->next;
        }

        block_t *to_free = block;
        block = block->next;
        free(to_free);
    }

    return block;
}

typedef struct coarse_memory_provider_t {
    umf_memory_provider_handle_t upstream_memory_provider;

    size_t used_size;
    size_t alloc_size;

    block_t *block_list;
    block_t *alloc_list;

    struct os_mutex_t *lock;

    bool trace;
} coarse_memory_provider_t;

#ifndef NDEBUG
static bool debug_check(coarse_memory_provider_t *provider) {
    assert(provider);

    size_t sum_used = 0;
    size_t sum_allocs_size = 0;
    size_t sum_blocks_size = 0;

    if (provider->block_list && provider->alloc_list) {
        assert(provider->block_list->data == provider->alloc_list->data);
    }

    block_t *block = provider->block_list;
    while (block) {
        assert(block->data);
        assert(block->size > 0);
        assert(block->origin);
        assert(block->origin->data);
        assert(block->data >= block->origin->data);
        assert(block->data < (block->origin->data + block->origin->size));

        // only the HEAD could have an empty prev
        if (block != provider->block_list) {
            assert(block->prev);
        }

        // check double-linking
        if (block->prev) {
            assert(block->prev->next == block);
        }

        if (block->next) {
            assert(block->next->prev == block);
        }

        // there shouldn't be two adjacent not-used blocks
        // if they allocs are continuous
        if (block->prev && block->used == false &&
            (block->prev->data + block->prev->size == block->data)) {
            assert(block->prev->used == true);
        }

        if (block->next && block->used == false &&
            (block->data + block->size == block->next->data)) {
            assert(block->next->used == true);
        }

        // data addresses in the list are in ascending order
        if (block->prev) {
            assert(block->prev->data < block->data);
        }

        if (block->next) {
            assert(block->data < block->next->data);
        }

        // two block's data should not overlap
        if (block->next) {
            assert((block->data + block->size) <= block->next->data);
        }

        // allocs used in block should be continuous
        block_t *alloc = block->origin;
        size_t alloc_offset = block->data - block->origin->data;
        size_t block_size_w_off = block->size + alloc_offset;
        size_t allocs_sum = alloc->size;
        while (allocs_sum < block_size_w_off) {
            assert(alloc->next);
            assert((alloc->data + alloc->size) == alloc->next->data);
            alloc = alloc->next;
            allocs_sum += alloc->size;
        }

        sum_blocks_size += block->size;
        if (block->used) {
            sum_used += block->size;
        }

        block = block->next;
    }

    assert(sum_used == provider->used_size);
    assert(sum_blocks_size == provider->alloc_size);
    assert(provider->alloc_size >= provider->used_size);

    block_t *alloc = provider->alloc_list;
    while (alloc) {
        assert(alloc->data);
        assert(alloc->size > 0);

        // only the HEAD could have an empty prev
        if (alloc != provider->alloc_list) {
            assert(alloc->prev);
        }

        // check double-linking
        if (alloc->prev) {
            assert(alloc->prev->next == alloc);
        }

        if (alloc->next) {
            assert(alloc->next->prev == alloc);
        }

        // data addresses in the list are in ascending order
        if (alloc->prev) {
            assert(alloc->prev->data < alloc->data);
        }

        if (alloc->next) {
            assert(alloc->data < alloc->next->data);
        }

        // data should not overlap
        if (alloc->next) {
            assert((alloc->data + alloc->size) <= alloc->next->data);
        }

        sum_allocs_size += alloc->size;

        alloc = alloc->next;
    }

    assert(sum_allocs_size == provider->alloc_size);

    return true;
}
#endif

static enum umf_result_t coarse_memory_provider_initialize(void *params,
                                                           void **provider) {
    void *init_buffer = NULL;

    if (provider == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (params == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    // check params
    coarse_memory_provider_params_t *coarse_params =
        (coarse_memory_provider_params_t *)params;
    if (coarse_params->upstream_memory_provider == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    coarse_memory_provider_t *coarse_provider =
        (coarse_memory_provider_t *)malloc(sizeof(coarse_memory_provider_t));

    if (!coarse_provider) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    coarse_provider->lock = util_mutex_create();
    if (coarse_provider->lock == NULL) {
        free(coarse_provider);
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    coarse_provider->trace = coarse_params->trace;
    coarse_provider->upstream_memory_provider =
        coarse_params->upstream_memory_provider;
    coarse_provider->block_list = NULL;
    coarse_provider->alloc_list = NULL;
    coarse_provider->alloc_size = 0;
    coarse_provider->used_size = 0;

    if (coarse_params->immediate_init) {
        coarse_memory_provider_alloc(
            coarse_provider, coarse_params->init_buffer_size, 0, &init_buffer);

        if (init_buffer == NULL) {
            util_mutex_destroy(coarse_provider->lock);
            free(coarse_provider);
            return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
        }

        // since we use alloc func, we have set the block as unused
        coarse_provider->used_size = 0;
        coarse_provider->block_list->used = false;
        coarse_provider->alloc_size = coarse_params->init_buffer_size;
    }

    *provider = coarse_provider;

    assert(debug_check(coarse_provider));

    return UMF_RESULT_SUCCESS;
}

static void coarse_memory_provider_finalize(void *provider) {
    if (provider == NULL) {
        assert(0);
        return;
    }

    coarse_memory_provider_t *coarse_provider =
        (struct coarse_memory_provider_t *)provider;

    block_t *alloc = coarse_provider->alloc_list;
    while (alloc) {
        enum umf_result_t ret =
            umfMemoryProviderFree(coarse_provider->upstream_memory_provider,
                                  alloc->data, alloc->size);

        // We would continue to deallocate alloc blocks even if the upstream
        // provider doesn't return success.
        assert(ret == UMF_RESULT_SUCCESS);
        (void)ret;

        assert(coarse_provider->alloc_size >= alloc->size);
        coarse_provider->alloc_size -= alloc->size;

        block_t *to_free = alloc;
        alloc = alloc->next;
        free(to_free);
    }
    assert(coarse_provider->alloc_size == 0);

    block_t *block = coarse_provider->block_list;
    while (block) {
        block_t *to_free = block;
        block = block->next;
        free(to_free);
    }

    util_mutex_destroy(coarse_provider->lock);
    free(coarse_provider);
}

static enum umf_result_t coarse_memory_provider_alloc(void *provider,
                                                      size_t size,
                                                      size_t alignment,
                                                      void **resultPtr) {
    enum umf_result_t ret = UMF_RESULT_SUCCESS;

    if (provider == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (resultPtr == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    coarse_memory_provider_t *coarse_provider =
        (struct coarse_memory_provider_t *)provider;
    assert(debug_check(coarse_provider));

    if (util_mutex_lock(coarse_provider->lock) != 0) {
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    // Try to reuse existing blocks first.
    // If the block that we want to reuse is has greater size, split it.
    // Try to merge split part with the successor if it is not used.
    block_t *curr = coarse_provider->block_list;
    while (curr) {
        if (!curr->used && (curr->size > size)) {
            // Split the existing block and put the new block after the existing.
            // Find the origin of the new block.
            size_t curr_offset = curr->data - curr->origin->data;
            block_t *origin =
                alloc_find_origin(curr->origin, curr_offset + size);
            assert(origin);
            void *data = curr->data + size;

            block_t *new_block = block_list_add(&coarse_provider->block_list,
                                                data, curr->size - size);
            if (new_block == NULL) {
                if (util_mutex_unlock(coarse_provider->lock) != 0) {
                    return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
                }

                return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
            }

            new_block->origin = origin;
            new_block->used = false;

            curr->used = true;
            curr->size = size;

            *resultPtr = curr->data;
            coarse_provider->used_size += size;

            if (coarse_provider->trace) {
                printf("coarse_ALLOC (split_block) %lu used %lu alloc %lu\n",
                       size, coarse_provider->used_size,
                       coarse_provider->alloc_size);
            }

            // Try to merge new empty block with the next one.
            new_block =
                block_merge_with_next(new_block, &coarse_provider->block_list);

            if (util_mutex_unlock(coarse_provider->lock) != 0) {
                return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
            }

            assert(debug_check(coarse_provider));
            return UMF_RESULT_SUCCESS;
        } else if (!curr->used && (curr->size == size)) {
            curr->used = true;
            *resultPtr = curr->data;
            coarse_provider->used_size += size;

            if (coarse_provider->trace) {
                printf("coarse_ALLOC (same_block) %lu used %lu alloc %lu\n",
                       size, coarse_provider->used_size,
                       coarse_provider->alloc_size);
            }

            if (util_mutex_unlock(coarse_provider->lock) != 0) {
                return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
            }

            assert(debug_check(coarse_provider));
            return UMF_RESULT_SUCCESS;
        }

        curr = curr->next;
    }

    // TODO - reuse last block if it is empty

    // no suitable block - try to get more memory from the upstream provider
    assert(coarse_provider->upstream_memory_provider);

    umfMemoryProviderAlloc(coarse_provider->upstream_memory_provider, size,
                           alignment, resultPtr);

    if (*resultPtr == NULL) {
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    block_t *alloc =
        block_list_add(&coarse_provider->alloc_list, *resultPtr, size);

    if (alloc == NULL) {
        ret = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        goto alloc_error;
    }

    // create new block and add it to the list
    block_t *new_block =
        block_list_add(&coarse_provider->block_list, *resultPtr, size);

    if (new_block == NULL) {
        assert(0);
        ret = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        goto block_error;
    }

    new_block->used = true;
    new_block->origin = alloc;

    coarse_provider->alloc_size += size;
    coarse_provider->used_size += size;

    if (coarse_provider->trace) {
        printf("coarse_ALLOC (upstream) %lu used %lu alloc %lu\n", size,
               coarse_provider->used_size, coarse_provider->alloc_size);
    }

    if (util_mutex_unlock(coarse_provider->lock) != 0) {
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    assert(debug_check(coarse_provider));
    return UMF_RESULT_SUCCESS;

block_error:
    free(alloc);

alloc_error:
    umfMemoryProviderFree(coarse_provider->upstream_memory_provider, *resultPtr,
                          size);
    return ret;
}

static enum umf_result_t coarse_memory_provider_free(void *provider, void *ptr,
                                                     size_t bytes) {
    if (provider == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    coarse_memory_provider_t *coarse_provider =
        (struct coarse_memory_provider_t *)provider;
    assert(debug_check(coarse_provider));

    if (util_mutex_lock(coarse_provider->lock) != 0) {
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    block_t *block = coarse_provider->block_list;
    while (block && block->data != ptr) {
        block = block->next;
    }

    if (block == NULL) {
        // the block was not found
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    if (bytes) {
        assert(bytes == block->size);
    }

    if (coarse_provider->trace) {
        printf("coarse_FREE (return_block_to_pool) %lu used %lu alloc %lu\n",
               block->size, coarse_provider->used_size - block->size,
               coarse_provider->alloc_size);
    }

    assert(coarse_provider->used_size >= block->size);
    coarse_provider->used_size -= block->size;

    block->used = false;

    // Merge with prev and/or next block if they are unused and have continuous
    // data.
    block = block_merge_with_prev(block);
    block = block_merge_with_next(block, &coarse_provider->block_list);

    assert(debug_check(coarse_provider));

    if (util_mutex_unlock(coarse_provider->lock) != 0) {
        return UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC;
    }

    return UMF_RESULT_SUCCESS;
}

static void coarse_memory_provider_get_last_native_error(void *provider,
                                                         const char **ppMessage,
                                                         int32_t *pError) {
    if (provider == NULL) {
        return;
    }

    (void)ppMessage;
    (void)pError;
    assert(0);
}

static enum umf_result_t
coarse_memory_provider_get_min_page_size(void *provider, void *ptr,
                                         size_t *pageSize) {
    if (provider == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    coarse_memory_provider_t *coarse_provider =
        (struct coarse_memory_provider_t *)provider;

    assert(coarse_provider->upstream_memory_provider);
    enum umf_result_t ret = umfMemoryProviderGetMinPageSize(
        coarse_provider->upstream_memory_provider, ptr, pageSize);

    return ret;
}

static enum umf_result_t
coarse_memory_provider_get_recommended_page_size(void *provider, size_t size,
                                                 size_t *pageSize) {
    if (provider == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    coarse_memory_provider_t *coarse_provider =
        (struct coarse_memory_provider_t *)provider;

    assert(coarse_provider->upstream_memory_provider);
    enum umf_result_t ret = umfMemoryProviderGetRecommendedPageSize(
        coarse_provider->upstream_memory_provider, size, pageSize);

    return ret;
}

static const char *coarse_memory_provider_get_name(void *provider) {
    (void)provider;

    return "coarse";
}

struct umf_memory_provider_ops_t UMF_COARSE_MEMORY_PROVIDER_OPS = {
    .version = UMF_VERSION_CURRENT,
    .initialize = coarse_memory_provider_initialize,
    .finalize = coarse_memory_provider_finalize,
    .alloc = coarse_memory_provider_alloc,
    .free = coarse_memory_provider_free,
    .get_last_native_error = coarse_memory_provider_get_last_native_error,
    .get_recommended_page_size =
        coarse_memory_provider_get_recommended_page_size,
    .get_min_page_size = coarse_memory_provider_get_min_page_size,
    .get_name = coarse_memory_provider_get_name,
};

coarse_memory_provider_stats_t umfCoarseMemoryProviderGetStats(void *provider) {
    assert(provider);

    coarse_memory_provider_t *coarse_provider =
        (struct coarse_memory_provider_t *)provider;

    // count blocks
    size_t blocks_num = 0;
    block_t *block = coarse_provider->block_list;
    while (block) {
        blocks_num++;
        block = block->next;
    }

    coarse_memory_provider_stats_t stats;
    stats.alloc_size = coarse_provider->alloc_size;
    stats.used_size = coarse_provider->used_size;
    stats.blocks_num = blocks_num;

    return stats;
}
