/*
 *
 * Copyright (C) 2023-2025 Intel Corporation
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
#include "base_alloc_global.h"
#include "test_helpers.h"
#include "utils/cpp_helpers.hpp"

typedef void *(*pfnProviderParamsCreate)();
typedef umf_result_t (*pfnProviderParamsDestroy)(void *);

using providerCreateExtParams =
    std::tuple<const umf_memory_provider_ops_t *, void *>;

std::string providerCreateExtParamsNameGen(
    const testing::TestParamInfo<providerCreateExtParams> param) {
    const umf_memory_provider_ops_t *provider_ops = std::get<0>(param.param);

    const char *providerName = NULL;
    provider_ops->get_name(NULL, &providerName);

    return providerName;
}

void providerCreateExt(providerCreateExtParams params,
                       umf_test::provider_unique_handle_t *handle) {
    umf_memory_provider_handle_t hProvider = nullptr;
    auto [provider_ops, provider_params] = params;

    auto ret =
        umfMemoryProviderCreate(provider_ops, provider_params, &hProvider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(hProvider, nullptr);

    *handle = umf_test::provider_unique_handle_t(hProvider,
                                                 &umfMemoryProviderDestroy);
}

namespace umf_test {

umf_memory_provider_handle_t
createProviderChecked(umf_memory_provider_ops_t *ops, void *params) {
    umf_memory_provider_handle_t hProvider;
    auto ret = umfMemoryProviderCreate(ops, params, &hProvider);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    return hProvider;
}

auto wrapProviderUnique(umf_memory_provider_handle_t hProvider) {
    return umf_test::provider_unique_handle_t(hProvider,
                                              &umfMemoryProviderDestroy);
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
    umf_result_t get_last_native_error(const char **, int32_t *) noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }
    umf_result_t
    get_recommended_page_size([[maybe_unused]] size_t size,
                              [[maybe_unused]] size_t *pageSize) noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }
    umf_result_t get_min_page_size([[maybe_unused]] const void *ptr,
                                   [[maybe_unused]] size_t *pageSize) noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }
    umf_result_t get_name(const char **name) noexcept {
        *name = "base";
        return UMF_RESULT_SUCCESS;
    }
    umf_result_t ext_purge_lazy([[maybe_unused]] void *ptr,
                                [[maybe_unused]] size_t size) noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }
    umf_result_t ext_purge_force([[maybe_unused]] void *ptr,
                                 [[maybe_unused]] size_t size) noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    umf_result_t ext_allocation_merge([[maybe_unused]] void *lowPtr,
                                      [[maybe_unused]] void *highPtr,
                                      [[maybe_unused]] size_t totalSize) {
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    umf_result_t ext_allocation_split([[maybe_unused]] void *ptr,
                                      [[maybe_unused]] size_t totalSize,
                                      [[maybe_unused]] size_t firstSize) {
        return UMF_RESULT_ERROR_UNKNOWN;
    }
    umf_result_t
    ext_get_ipc_handle_size([[maybe_unused]] size_t *size) noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }
    umf_result_t
    ext_get_ipc_handle([[maybe_unused]] const void *ptr,
                       [[maybe_unused]] size_t size,
                       [[maybe_unused]] void *providerIpcData) noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }
    umf_result_t
    ext_put_ipc_handle([[maybe_unused]] void *providerIpcData) noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }
    umf_result_t ext_open_ipc_handle([[maybe_unused]] void *providerIpcData,
                                     [[maybe_unused]] void **ptr) noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }
    umf_result_t ext_close_ipc_handle([[maybe_unused]] void *ptr,
                                      [[maybe_unused]] size_t size) noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    umf_result_t ext_ctl([[maybe_unused]] umf_ctl_query_source_t source,
                         [[maybe_unused]] const char *name,
                         [[maybe_unused]] void *arg,
                         [[maybe_unused]] size_t size,
                         [[maybe_unused]] umf_ctl_query_type_t queryType,
                         [[maybe_unused]] va_list args) noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    umf_result_t ext_get_allocation_properties(
        [[maybe_unused]] const void *ptr,
        [[maybe_unused]] umf_memory_property_id_t memory_property_id,
        [[maybe_unused]] void *value) noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    umf_result_t ext_get_allocation_properties_size(
        [[maybe_unused]] umf_memory_property_id_t memory_property_id,
        [[maybe_unused]] size_t *size) noexcept {
        return UMF_RESULT_ERROR_UNKNOWN;
    }

    virtual ~provider_base_t() = default;
} provider_base_t;

umf_memory_provider_ops_t BASE_PROVIDER_OPS =
    umf_test::providerMakeCOps<provider_base_t, void>();

struct provider_ba_global : public provider_base_t {
    umf_result_t alloc(size_t size, size_t align, void **ptr) noexcept {
        if (!align) {
            align = 8;
        }

        // aligned_malloc returns a valid pointer despite not meeting the
        // requirement of 'size' being multiple of 'align' even though the
        // documentation says that it has to. AddressSanitizer returns an
        // error because of this issue.
        size_t aligned_size = ALIGN_UP_SAFE(size, align);
        if (aligned_size == 0) {
            return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        }

        *ptr = umf_ba_global_aligned_alloc(aligned_size, align);

        return (*ptr) ? UMF_RESULT_SUCCESS
                      : UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }
    umf_result_t free(void *ptr, size_t) noexcept {
        umf_ba_global_free(ptr);
        return UMF_RESULT_SUCCESS;
    }
    umf_result_t get_name(const char **name) noexcept {
        *name = "umf_ba_global";
        return UMF_RESULT_SUCCESS;
    }
};

umf_memory_provider_ops_t BA_GLOBAL_PROVIDER_OPS =
    umf_test::providerMakeCOps<provider_ba_global, void>();

struct provider_mock_out_of_mem : public provider_base_t {
    provider_ba_global helper_prov;
    int allocNum = 0;
    umf_result_t initialize(const int *inAllocNum) noexcept {
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
    umf_result_t get_name(const char **name) noexcept {
        *name = "mock_out_of_mem";
        return UMF_RESULT_SUCCESS;
    }
};

const umf_memory_provider_ops_t MOCK_OUT_OF_MEM_PROVIDER_OPS =
    umf_test::providerMakeCOps<provider_mock_out_of_mem, int>();

} // namespace umf_test

#endif /* UMF_TEST_PROVIDER_HPP */
