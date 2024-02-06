// Copyright (C) 2023 Intel Corporation
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
    std::unordered_map<void *, size_t> sizes;
    std::mutex m;

    void *malloc(size_t size) noexcept {
        auto *ptr = umf_ba_global_alloc(size);
        std::unique_lock<std::mutex> l(m);
        sizes[ptr] = size;
        return ptr;
    }
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
        std::unique_lock<std::mutex> l(m);
        return sizes[ptr];
    }
    umf_result_t free(void *ptr) noexcept {
        size_t size;
        {
            std::unique_lock<std::mutex> l(m);
            size = sizes[ptr];
        }

        umf_ba_global_free(ptr, size);
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
