/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_MEMORY_RESOURCE_H
#define UMF_MEMORY_RESOURCE_H 1

#include <memory_resource>

#include <umf/base.h>
#include <umf/memory_pool.h>
#include <umf/memory_provider.h>
#include <umf/pools/pool_disjoint.h>

namespace umf {

namespace detail {

// TODO: should this be implemented in the header?
umf_result_t umfMemoryProviderFromResource(std::pmr::memory_resource *resource,
                                           umf_memory_provider_handle_t *out);

class pool_resource : public std::pmr::memory_resource {
  public:
    pool_resource(std::pmr::memory_resource *upstream,
                  umf_memory_pool_ops_t *ops, void *params) {
        umf_memory_provider_handle_t hProvider;
        auto ret = umfMemoryProviderFromResource(upstream, &hProvider);
        if (ret != UMF_RESULT_SUCCESS) {
            throw ret;
        }

        // TODO: use 'owning' version of create or return unique_ptr from umfMemoryProviderFromResource
        ret = umfPoolCreate(ops, hProvider, params, &hPool);
        if (ret != UMF_RESULT_SUCCESS) {
            throw ret;
        }
    }

    pool_resource(const pool_resource &) = delete;
    pool_resource &operator=(const pool_resource &Other) = delete;

    void *do_allocate(std::size_t bytes, std::size_t alignment) {
        // TODO: add error checking and throw exception
        return umfPoolAlignedMalloc(hPool, bytes, alignment);
    }

    void do_deallocate(void *p, std::size_t, std::size_t) {
        // TODO: consider allowing to free memory coming from different pools
        // (call umfFree(p))
        auto ret = umfPoolFree(hPool, p);
        if (ret != UMF_RESULT_SUCCESS) {
            throw ret;
        }
    }

    bool do_is_equal(const std::pmr::memory_resource &other) const noexcept {
        return this == &other;
    }

  private:
    umf_memory_pool_handle_t hPool;
};
} // namespace detail

class disjoint_pool_resource : public detail::pool_resource {
  public:
    using options = umf_disjoint_pool_params;
    disjoint_pool_resource(std::pmr::memory_resource *upstream,
                           const options &opts = umfDisjointPoolParamsDefault())
        : detail::pool_resource(upstream, &UMF_DISJOINT_POOL_OPS,
                                (void *)&opts) {}
};
} // namespace umf

#endif
