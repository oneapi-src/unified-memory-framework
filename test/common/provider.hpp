/*
 *
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_TEST_PROVIDER_HPP
#define UMF_TEST_PROVIDER_HPP 1

#include <umf/base.h>
#include <umf/memory_provider.h>

#include "base.hpp"
#include "cpp_helpers.hpp"
#include "test_helpers.h"

namespace umf_test {

umf_memory_provider_handle_t
createProviderChecked(umf_memory_provider_ops_t *ops, void *params) {
    umf_memory_provider_handle_t hProvider;
    auto ret = umfMemoryProviderCreate(ops, params, &hProvider);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    return hProvider;
}

auto wrapProviderUnique(umf_memory_provider_handle_t hProvider) {
    return umf::provider_unique_handle_t(hProvider, &umfMemoryProviderDestroy);
}

typedef struct provider_base_t {
    umf_result_t initialize() noexcept { return UMF_RESULT_SUCCESS; };
    umf_result_t alloc(size_t, size_t, void **) noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }
    umf_result_t free([[maybe_unused]] void *ptr,
                      [[maybe_unused]] size_t size) noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }
    void get_last_native_error(const char **, int32_t *) noexcept {}
    umf_result_t
    get_recommended_page_size([[maybe_unused]] size_t size,
                              [[maybe_unused]] size_t *pageSize) noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }
    umf_result_t get_min_page_size([[maybe_unused]] void *ptr,
                                   [[maybe_unused]] size_t *pageSize) noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }
    const char *get_name() noexcept { return "base"; }
    umf_result_t purge_lazy([[maybe_unused]] void *ptr,
                            [[maybe_unused]] size_t size) noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }
    umf_result_t purge_force([[maybe_unused]] void *ptr,
                             [[maybe_unused]] size_t size) noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    umf_result_t allocation_merge([[maybe_unused]] void *lowPtr,
                                  [[maybe_unused]] void *highPtr,
                                  [[maybe_unused]] size_t totalSize) {
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    umf_result_t allocation_split([[maybe_unused]] void *ptr,
                                  [[maybe_unused]] size_t totalSize,
                                  [[maybe_unused]] size_t firstSize) {
        return UMF_RESULT_ERROR_UNKNOWN;
    }
    umf_result_t get_ipc_handle_size([[maybe_unused]] size_t *size) noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }
    umf_result_t
    get_ipc_handle([[maybe_unused]] const void *ptr,
                   [[maybe_unused]] size_t size,
                   [[maybe_unused]] void *providerIpcData) noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }
    umf_result_t
    put_ipc_handle([[maybe_unused]] void *providerIpcData) noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }
    umf_result_t open_ipc_handle([[maybe_unused]] void *providerIpcData,
                                 [[maybe_unused]] void **ptr) noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }
    umf_result_t close_ipc_handle([[maybe_unused]] void *ptr,
                                  [[maybe_unused]] size_t size) noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }
    virtual ~provider_base_t() = default;
} provider_base_t;

umf_memory_provider_ops_t BASE_PROVIDER_OPS =
    umf::providerMakeCOps<provider_base_t, void>();

struct provider_malloc : public provider_base_t {
    umf_result_t alloc(size_t size, size_t align, void **ptr) noexcept {
        if (!align) {
            align = 8;
        }

        // aligned_malloc returns a valid pointer despite not meeting the
        // requirement of 'size' being multiple of 'align' even though the
        // documentation says that it has to. AddressSanitizer returns an
        // error because of this issue.
        size_t aligned_size = ALIGN_UP(size, align);

#ifdef _WIN32
        *ptr = _aligned_malloc(aligned_size, align);
#else
        *ptr = ::aligned_alloc(align, aligned_size);
#endif

        return (*ptr) ? UMF_RESULT_SUCCESS
                      : UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }
    umf_result_t free(void *ptr, size_t) noexcept {
#ifdef _WIN32
        _aligned_free(ptr);
#else
        ::free(ptr);
#endif
        return UMF_RESULT_SUCCESS;
    }
    const char *get_name() noexcept { return "malloc"; }
};

umf_memory_provider_ops_t MALLOC_PROVIDER_OPS =
    umf::providerMakeCOps<provider_malloc, void>();

struct provider_mock_out_of_mem : public provider_base_t {
    provider_malloc helper_prov;
    int allocNum = 0;
    umf_result_t initialize(int *inAllocNum) noexcept {
        allocNum = *inAllocNum;
        return UMF_RESULT_SUCCESS;
    }
    umf_result_t alloc(size_t size, size_t align, void **ptr) noexcept {
        if (allocNum <= 0) {
            *ptr = nullptr;
            return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        }
        allocNum--;

        return helper_prov.alloc(size, align, ptr);
    }
    umf_result_t free(void *ptr, size_t size) noexcept {
        return helper_prov.free(ptr, size);
    }
    const char *get_name() noexcept { return "mock_out_of_mem"; }
};

umf_memory_provider_ops_t MOCK_OUT_OF_MEM_PROVIDER_OPS =
    umf::providerMakeCOps<provider_mock_out_of_mem, int>();

} // namespace umf_test

#endif /* UMF_TEST_PROVIDER_HPP */
