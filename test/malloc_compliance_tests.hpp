// Copyright (C) 2023 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#ifndef UMF_TEST_MALLOC_COMPLIANCE_TESTS_H
#define UMF_TEST_MALLOC_COMPLIANCE_TESTS_H

#include "umf/memory_pool.h"

void malloc_compliance_test(umf_memory_pool_handle_t hPool);
void calloc_compliance_test(umf_memory_pool_handle_t hPool);
void realloc_compliance_test(umf_memory_pool_handle_t hPool);
void free_compliance_test(umf_memory_pool_handle_t hPool);

#endif /* UMF_TEST_MALLOC_COMPLIANCE_TESTS_H */
