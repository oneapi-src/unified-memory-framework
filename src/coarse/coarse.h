/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#ifndef UMF_COARSE_H
#define UMF_COARSE_H

#include <stdbool.h>
#include <string.h>

#include <umf/base.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct coarse_t coarse_t;

// coarse callbacks implement provider-specific actions
typedef struct coarse_callbacks_t {
    // alloc() is optional (can be NULL for the fixed-size memory provider)
    umf_result_t (*alloc)(void *provider, size_t size, size_t alignment,
                          void **ptr);
    // free() is optional (can be NULL if the provider does not support the free() op)
    umf_result_t (*free)(void *provider, void *ptr, size_t size);
    umf_result_t (*split)(void *provider, void *ptr, size_t totalSize,
                          size_t firstSize);
    umf_result_t (*merge)(void *provider, void *lowPtr, void *highPtr,
                          size_t totalSize);
} coarse_callbacks_t;

// coarse library allocation strategy
typedef enum coarse_strategy_t {
    // Check if the first free block of the 'size' size has the correct alignment.
    // If not, use the `UMF_COARSE_MEMORY_STRATEGY_FASTEST` strategy.
    UMF_COARSE_MEMORY_STRATEGY_FASTEST_BUT_ONE = 0,

    // Always allocate a free block of the (size + alignment) size
    // and cut out the properly aligned part leaving two remaining parts.
    // It is the fastest strategy but causes memory fragmentation
    // when alignment is greater than 0.
    // It is the best strategy when alignment always equals 0.
    UMF_COARSE_MEMORY_STRATEGY_FASTEST,

    // Look through all free blocks of the 'size' size
    // and choose the first one with the correct alignment.
    // If none of them had the correct alignment,
    // use the `UMF_COARSE_MEMORY_STRATEGY_FASTEST` strategy.
    UMF_COARSE_MEMORY_STRATEGY_CHECK_ALL_SIZE,
} coarse_strategy_t;

// coarse library settings structure
typedef struct coarse_params_t {
    // handle of the memory provider
    void *provider;

    // coarse callbacks
    coarse_callbacks_t cb;

    // memory allocation strategy,
    // see coarse_strategy_t for details
    coarse_strategy_t allocation_strategy;

    // page size of the memory provider
    size_t page_size;
} coarse_params_t;

// coarse library statistics
typedef struct coarse_stats_t {
    // total allocation size
    size_t alloc_size;

    // size of used memory
    size_t used_size;

    // total number of allocated memory blocks
    size_t num_all_blocks;

    // number of free memory blocks
    size_t num_free_blocks;
} coarse_stats_t;

umf_result_t coarse_new(coarse_params_t *coarse_params, coarse_t **pcoarse);
void coarse_delete(coarse_t *coarse);

umf_result_t coarse_alloc(coarse_t *coarse, size_t size, size_t alignment,
                          void **resultPtr);
umf_result_t coarse_free(coarse_t *coarse, void *ptr, size_t bytes);

umf_result_t coarse_merge(coarse_t *coarse, void *lowPtr, void *highPtr,
                          size_t totalSize);
umf_result_t coarse_split(coarse_t *coarse, void *ptr, size_t totalSize,
                          size_t firstSize);

// supported only if the alloc callback is set,
// returns UMF_RESULT_ERROR_NOT_SUPPORTED otherwise
umf_result_t coarse_add_memory_from_provider(coarse_t *coarse, size_t size);

// supported only if the alloc and the free callbacks are NOT set
// returns UMF_RESULT_ERROR_NOT_SUPPORTED otherwise
umf_result_t coarse_add_memory_fixed(coarse_t *coarse, void *addr, size_t size);

coarse_stats_t coarse_get_stats(coarse_t *coarse);

#ifdef __cplusplus
}
#endif

#endif // UMF_COARSE_H
