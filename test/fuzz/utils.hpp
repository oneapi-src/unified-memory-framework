// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#ifndef UMF_TEST_FUZZ_UTILS_HPP
#define UMF_TEST_FUZZ_UTILS_HPP

#include "umf/pools/pool_scalable.h"
#include "umf/providers/provider_os_memory.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <map>
#include <memory>
#include <vector>

namespace fuzz {

enum FuzzerAPICall : uint8_t {
    UMF_MEMORY_PROVIDER_ALLOC,
    UMF_MEMORY_PROVIDER_FREE,
    UMF_POOL_CREATE,
    UMF_POOL_DESTROY,
    UMF_POOL_MALLOC,
    UMF_POOL_FREE,
    kMaxValue = UMF_POOL_FREE,
};

struct TestState {
    std::unique_ptr<FuzzedDataProvider> data_provider;
    umf_memory_provider_handle_t provider;
    std::vector<std::pair<void *, size_t>> provider_memory_allocations;
    std::map<umf_memory_pool_handle_t, std::vector<void *>> pools;

    TestState(std::unique_ptr<FuzzedDataProvider> data_provider)
        : data_provider(std::move(data_provider)) {}

    template <typename IntType> int get_next_input_data(IntType *data) {
        if (data_provider->remaining_bytes() < sizeof(IntType)) {
            return -1;
        }
        *data = data_provider->ConsumeIntegral<IntType>();

        return 0;
    }

    template <typename IntType>
    int get_next_input_data_in_range(IntType *data, IntType min, IntType max) {
        if (data_provider->remaining_bytes() < sizeof(IntType)) {
            return -1;
        }
        *data = data_provider->ConsumeIntegralInRange<IntType>(min, max);

        return 0;
    }

    template <typename EnumType> int get_next_input_data_enum(EnumType *data) {
        if (data_provider->remaining_bytes() < sizeof(EnumType)) {
            return -1;
        }
        *data = data_provider->ConsumeEnum<EnumType>();

        return 0;
    }

    int get_next_api_call() {
        FuzzerAPICall next_api_call;
        return get_next_input_data_enum(&next_api_call) == 0 ? next_api_call
                                                             : -1;
    }

    size_t get_next_alloc_size(TestState &state, size_t &alloc_size,
                               size_t max_alloc_size) {
        if (state.get_next_input_data_in_range<size_t>(&alloc_size, 0,
                                                       max_alloc_size) != 0) {
            return -1;
        }
        return 0;
    }
};
} // namespace fuzz

#endif /* UMF_TEST_FUZZ_UTILS_HPP */
