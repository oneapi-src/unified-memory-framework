// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "memory_target_numa.h"
#include "memspace_helpers.hpp"
#include "memspace_internal.h"
#include "test_helpers.h"

#include <numa.h>
#include <numaif.h>
#include <umf/memspace.h>

using umf_test::test;

TEST_F(numaNodesTest, memspaceGet) {
    umf_memspace_handle_t hMemspace = umfMemspaceHighestBandwidthGet();
    UT_ASSERTne(hMemspace, nullptr);
}
