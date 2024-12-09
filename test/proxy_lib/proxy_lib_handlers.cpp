/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#if defined(__APPLE__)
#include <malloc/malloc.h>
#else
#include <malloc.h>
#endif

#include <umf/proxy_lib_handlers.h>

#include "base.hpp"
#include "test_helpers.h"
#include "utils_common.h"

using umf_test::test;

#define SIZE_64 64
#define ALIGN_1024 1024

static int free_cnt = 0;
void handler_free_pre(void *ptr, umf_memory_pool_handle_t pool) {
    (void)ptr;
    (void)pool;
    free_cnt += 1;
}

TEST_F(test, proxyLib_handlers_free) {

    void *ptr = ::malloc(SIZE_64);
    ASSERT_NE(ptr, nullptr);

    umfSetProxyLibHandlerFreePre(handler_free_pre);
    ASSERT_EQ(free_cnt, 0);

    ::free(ptr);
    ASSERT_EQ(free_cnt, 1);
}
