// Copyright (C) 2023 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// This file contains tests for UMF provider API

#include <memory_resource>

#include "provider.hpp"
#include "test_helpers.h"
#include <umf/memory_resource.hpp>

using umf_test::test;

TEST_F(test, disjointPoolResourceWithNewDelete) {
    static constexpr size_t alloc_size = 16;

    auto upstream_resource = std::pmr::new_delete_resource();
    auto pool = umf::disjoint_pool_resource(upstream_resource);

    auto *ptr = pool.allocate(alloc_size);
    ASSERT_NE(ptr, nullptr);

    pool.deallocate(ptr, alloc_size);
}
