// Copyright (C) 2023-2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <unordered_map>

#include "umf/pools/pool_scalable.h"
#include "umf/providers/provider_os_memory.h"

#include "pool.hpp"
#include "poolFixtures.hpp"
#include "provider.hpp"

#include "base_alloc_global.h"

struct base_alloc_pool : public umf_test::pool_base_t {

    void *malloc(size_t size) noexcept { return umf_ba_global_alloc(size); }
    void *calloc(size_t, size_t) noexcept {
        umf::getPoolLastStatusRef<base_alloc_pool>() =
            UMF_RESULT_ERROR_NOT_SUPPORTED;
        return NULL;
    }
    void *realloc(void *, size_t) noexcept {
        umf::getPoolLastStatusRef<base_alloc_pool>() =
            UMF_RESULT_ERROR_NOT_SUPPORTED;
        return NULL;
    }
    void *aligned_malloc(size_t, size_t) noexcept {
        umf::getPoolLastStatusRef<base_alloc_pool>() =
            UMF_RESULT_ERROR_NOT_SUPPORTED;
        return NULL;
    }
    size_t malloc_usable_size(void *ptr) noexcept {
        return umf_ba_global_malloc_usable_size(ptr);
    }
    umf_result_t free(void *ptr) noexcept {
        umf_ba_global_free(ptr);
        return UMF_RESULT_SUCCESS;
    }
    umf_result_t get_last_allocation_error() {
        return umf::getPoolLastStatusRef<base_alloc_pool>();
    }
};

umf_memory_pool_ops_t BA_POOL_OPS = umf::poolMakeCOps<base_alloc_pool, void>();

INSTANTIATE_TEST_SUITE_P(baPool, umfPoolTest,
                         ::testing::Values(poolCreateExtParams{
                             &BA_POOL_OPS, nullptr,
                             &umf_test::BASE_PROVIDER_OPS, nullptr}));
