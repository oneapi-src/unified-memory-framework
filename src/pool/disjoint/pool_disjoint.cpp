// Copyright (C) 2023 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "pool/pool_disjoint.h"
#include "pool_disjoint_impl.hpp"
#include "umf_helpers.hpp"

struct umf_disjoint_pool_shared_limits *
umfDisjointPoolSharedLimitsCreate(size_t MaxSize) {
    return new umf_disjoint_pool_shared_limits{MaxSize, 0};
}

void umfDisjointPoolSharedLimitsDestroy(
    struct umf_disjoint_pool_shared_limits *limits) {
    delete limits;
}

struct umf_memory_pool_ops_t UMF_DISJOINT_POOL_OPS =
    umf::poolMakeCOps<usm::DisjointPool, umf_disjoint_pool_params>();
