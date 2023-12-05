/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <umf/memory_resource.hpp>

#include "common/umf_helpers.hpp"

namespace umf::detail {

class memory_provider_over_memory_resource {
  public:
    umf_result_t initialize(std::pmr::memory_resource *resource) noexcept {
        this->resource = resource;
        return UMF_RESULT_SUCCESS;

        // TODO: for some resources we can optimize the allocation path.
        // For example if we now that memory resource is using UMF underneath
        // we can try to extract the actual provider resource and use it
        // directly
    };

    umf_result_t alloc(size_t size, size_t alignment, void **ptr) noexcept try {
        *ptr = resource->allocate(size, alignment);
        return UMF_RESULT_SUCCESS;
    } catch (...) {
        // TODO: save exception and return through get_last_native_error
        return UMF_RESULT_ERROR_UNKNOWN;
    }
    umf_result_t free(void *ptr, size_t size) noexcept try {
        resource->deallocate(ptr, size);
        return UMF_RESULT_SUCCESS;
    } catch (...) {
        // TODO: save exception and return through get_last_native_error
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    void get_last_native_error(const char **, int32_t *) noexcept {
        // TODO
    }
    umf_result_t get_recommended_page_size(size_t, size_t *) noexcept {
        return UMF_RESULT_ERROR_NOT_SUPPORTED;
    }
    umf_result_t get_min_page_size(void *, size_t *) noexcept {
        return UMF_RESULT_ERROR_NOT_SUPPORTED;
    }
    umf_result_t purge_lazy(void *, size_t) noexcept {
        return UMF_RESULT_ERROR_NOT_SUPPORTED;
    }
    umf_result_t purge_force(void *, size_t) noexcept {
        return UMF_RESULT_ERROR_NOT_SUPPORTED;
    }
    const char *get_name() noexcept { return "TODO"; }

  private:
    std::pmr::memory_resource *resource;
};

umf_result_t umfMemoryProviderFromResource(std::pmr::memory_resource *resource,
                                           umf_memory_provider_handle_t *out) {
    auto [ret, hProvider] =
        umf::memoryProviderMakeUnique<memory_provider_over_memory_resource>(
            resource);
    *out = hProvider.release();
    return ret;
}
} // namespace umf::detail
