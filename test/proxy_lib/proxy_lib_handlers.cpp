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
#include <umf/proxy_lib_new_delete.h>

#include "base.hpp"
#include "test_helpers.h"
#include "utils_assert.h"
#include "utils_common.h"

using umf_test::test;

#define SIZE_64 64
#define ALIGN_1024 1024

static int free_cnt = 0;
void handler_free_pre(void *user_data, void **ptr,
                      umf_memory_pool_handle_t pool) {
    // NOTE: pool could be empty in case the alloc < threshold
    (void)pool;
    (void)ptr;

    // NOTE: we can't use google asserts here as they could call new/delete
    // which leads to an infinite recursion loop
    ASSERT(user_data != nullptr);
    ASSERT(ptr != nullptr);

    free_cnt += 1;

    // increment user data by 1
    (*(size_t *)user_data)++;
}

TEST_F(test, proxyLib_handlers_free) {
    void *ptr = ::malloc(SIZE_64);
    ASSERT_NE(ptr, nullptr);

    size_t user_data = 5;
    umfSetProxyLibHandlerFreePre(handler_free_pre, (void *)&user_data);
    ASSERT_EQ(free_cnt, 0);

    ::free(ptr);
    ASSERT_EQ(free_cnt, 1);
    ASSERT_EQ(user_data, 6);

    umfSetProxyLibHandlerFreePre(NULL, NULL);
}

struct user_data_t {
    size_t data;
};

static int malloc_pre_cnt = 0;
void handler_malloc_pre(void *user_data, size_t *size) {
    ASSERT(user_data != nullptr);
    ASSERT(size != nullptr);

    // do larger alloc - first few bytes would be reserved for user data
    // (incremented here)
    *size += sizeof(user_data_t);
    ((user_data_t *)user_data)->data += 1;

    malloc_pre_cnt += 1;
}

static int malloc_post_cnt = 0;
void handler_malloc_post(void *user_data, void **ptr,
                         umf_memory_pool_handle_t pool) {
    (void)pool;

    ASSERT(user_data != nullptr);
    ASSERT(ptr != nullptr);

    // fill first bytes would be filled with user_data
    memcpy(*ptr, user_data, sizeof(user_data_t));

    // shift ptr by 8 bytes so the app would not see user data
    *(uint8_t *)ptr += sizeof(user_data_t);

    malloc_post_cnt += 1;
}

void handler_free_pre2(void *user_data, void **ptr,
                       umf_memory_pool_handle_t pool) {
    // NOTE: pool could be empty in case the alloc < threshold
    (void)pool;
    (void)user_data;

    ASSERT(user_data != nullptr);
    ASSERT(ptr != nullptr);

    // in malloc we changed the size of ptr - we have to update the ptr here to
    // free the whole allocation
    *(uint8_t *)ptr -= sizeof(user_data_t);
}

TEST_F(test, proxyLib_handlers_malloc) {

    user_data_t user_data = {5};
    umfSetProxyLibHandlerMallocPre(handler_malloc_pre, &user_data);
    umfSetProxyLibHandlerMallocPost(handler_malloc_post, &user_data);

    void *ptr = ::malloc(SIZE_64);
    ASSERT_NE(ptr, nullptr);

    if (ptr == NULL) {
        // WA for windows checks
        return;
    }

    // set first and last byte to 1
    *(uint8_t *)ptr = 1;
    *((uint8_t *)ptr + SIZE_64 - 1) = 1;

    // check if user data is present in the first few bytes of allocation
    uint8_t *user_ptr = (uint8_t *)ptr - sizeof(user_data_t);
    ASSERT_EQ(((user_data_t *)user_ptr)->data, 6);
    ASSERT_EQ(user_data.data, 6);

    // check if the allaction data is correct (first and last byte)
    ASSERT_EQ(*(uint8_t *)ptr, 1);
    ASSERT_EQ(*((uint8_t *)ptr + SIZE_64 - 1), 1);

    ASSERT_EQ(malloc_pre_cnt, 1);
    ASSERT_EQ(malloc_post_cnt, 1);

    umfSetProxyLibHandlerFreePre(handler_free_pre2, (void *)&user_data);
    ::free(ptr);

    // IMPORTANT!
    // We have to strictly control which allocation will be modified by our
    // handlers. Cleanup them here so no further test/system allocations would
    // be affected
    umfSetProxyLibHandlerMallocPre(NULL, NULL);
    umfSetProxyLibHandlerMallocPost(NULL, NULL);
    umfSetProxyLibHandlerFreePre(NULL, NULL);
}
